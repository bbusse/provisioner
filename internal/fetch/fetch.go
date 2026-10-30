package fetch

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bbusse/provisioner/internal/apply"
	"github.com/bbusse/provisioner/internal/cms"
	"github.com/bbusse/provisioner/internal/devicefile"
)

type Fetcher struct {
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Sleep  func(time.Duration)
}

type trust struct {
	ca, pin, cert, key []byte
}

func (f *Fetcher) say(format string, args ...any) {
	fmt.Fprintf(f.Stdout, "provision: "+format+"\n", args...)
}

func (f *Fetcher) warn(format string, args ...any) {
	fmt.Fprintf(f.Stderr, "provision: "+format+"\n", args...)
}

func output(name string, args ...string) string {
	out, _ := exec.Command(name, args...).Output()
	return strings.TrimRight(string(out), "\n")
}

func readTrust(dir string) trust {
	read := func(name string) []byte {
		data, _ := os.ReadFile(filepath.Join(dir, "provision", name))
		return data
	}
	return trust{read("ca.pem"), read("pinnedpubkey"), read("client.pem"), read("client.key")}
}

func (f *Fetcher) trust() trust {
	if esp := f.Getenv("PROVISION_ESP"); esp != "" {
		return readTrust(esp)
	}
	root := filepath.Base(output("findmnt", "-nro", "SOURCE", "/"))
	if root == "" || root == "." {
		return trust{}
	}
	if _, err := os.Stat("/sys/class/block/" + root + "/partition"); err != nil {
		return trust{}
	}
	disk, err := filepath.EvalSymlinks("/sys/class/block/" + root + "/..")
	if err != nil {
		return trust{}
	}
	parts, _ := filepath.Glob("/sys/class/block/" + filepath.Base(disk) + "*/partition")
	esp := ""
	for _, p := range parts {
		if data, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(data)) == "2" {
			esp = "/dev/" + filepath.Base(filepath.Dir(p))
			break
		}
	}
	if esp == "" {
		return trust{}
	}
	mnt, _, _ := strings.Cut(output("findmnt", "-nro", "TARGET", "--source", esp), "\n")
	if mnt != "" {
		return readTrust(mnt)
	}
	own, err := os.MkdirTemp("", "provision-esp")
	if err != nil {
		return trust{}
	}
	defer os.Remove(own)
	if exec.Command("mount", "-t", "vfat", "-o", "ro", esp, own).Run() != nil {
		return trust{}
	}
	defer exec.Command("umount", own).Run()
	return readTrust(own)
}

func (f *Fetcher) waitForClock() {
	if _, err := exec.LookPath("timedatectl"); err != nil {
		return
	}
	limit, err := strconv.Atoi(f.Getenv("PROVISION_TIME_WAIT"))
	if err != nil {
		limit = 60
	}
	waited := 0
	for output("timedatectl", "show", "-p", "NTPSynchronized", "--value") != "yes" {
		if waited >= limit {
			f.warn("clock not synchronised after %ds, certificates may look not yet valid", waited)
			return
		}
		f.Sleep(2 * time.Second)
		waited += 2
	}
}

type entry struct {
	Address string `json:"address"`
	Port    any    `json:"port"`
}

func pickService(data []byte) string {
	var entries []entry
	if json.Unmarshal(data, &entries) != nil {
		return ""
	}
	best := ""
	bestRank := 2
	for _, e := range entries {
		addr, err := netip.ParseAddr(e.Address)
		if err != nil {
			continue
		}
		var port int
		switch p := e.Port.(type) {
		case float64:
			port = int(p)
		case string:
			port, _ = strconv.Atoi(p)
		}
		if port <= 0 || port >= 65536 || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
			continue
		}
		rank := 1
		if addr.Is4() || addr.Is4In6() {
			rank = 0
		}
		if rank < bestRank {
			bestRank = rank
			best = "https://" + net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(port))
		}
	}
	return best
}

func defaultGateway() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var ip [4]byte
		binary.LittleEndian.PutUint32(ip[:], binary.BigEndian.Uint32(raw))
		return netip.AddrFrom4(ip).String()
	}
	return ""
}

func (f *Fetcher) discover() string {
	if path, err := exec.LookPath("mdns-discover"); err == nil {
		timeout := f.Getenv("PROVISION_MDNS_TIMEOUT")
		if timeout == "" {
			timeout = "5s"
		}
		cmd := exec.Command(path, "--output=json", "--timeout="+timeout)
		cmd.Env = append(os.Environ(), "MDNS_SERVICE_FILTER=_provision._tcp")
		out, _ := cmd.Output()
		if url := pickService(out); url != "" {
			return url
		}
	}
	if gw := defaultGateway(); gw != "" {
		return "https://" + gw + ":8443"
	}
	return ""
}

func pins(data []byte) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(strings.TrimSpace(string(data)), ";") {
		if p = strings.TrimPrefix(strings.TrimSpace(p), "sha256//"); p != "" {
			out[p] = true
		}
	}
	return out
}

func (f *Fetcher) get(server string, t trust) ([]byte, error) {
	cert, err := tls.X509KeyPair(t.cert, t.key)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if len(t.ca) > 0 {
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(t.ca) {
			return nil, errors.New("provision/ca.pem holds no certificate")
		}
	} else {
		cfg.InsecureSkipVerify = true
	}
	if allowed := pins(t.pin); len(allowed) > 0 {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !allowed[base64.StdEncoding.EncodeToString(sum[:])] {
				return errors.New("the server's public key does not match provision/pinnedpubkey")
			}
			return nil
		}
	} else if len(t.ca) == 0 {
		f.warn("no CA certificate or pinned key on the ESP, not verifying %s", server)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil}, Timeout: 10 * time.Second}
	resp, err := client.Get(server + "/cgi-bin/provision")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

func (f *Fetcher) open(body []byte, server string, t trust) ([]byte, bool) {
	if !cms.IsPEM(body) {
		if len(t.ca) > 0 {
			f.warn("%s sent a provisioning file that is not sealed, refusing it", server)
			return nil, false
		}
		return body, true
	}
	der, err := cms.DecodePEM(body)
	var cert *x509.Certificate
	var signed []byte
	if err == nil {
		var tc tls.Certificate
		if tc, err = tls.X509KeyPair(t.cert, t.key); err == nil {
			if cert, err = x509.ParseCertificate(tc.Certificate[0]); err == nil {
				signed, err = cms.Decrypt(der, cert, tc.PrivateKey)
			}
		}
	}
	if err != nil {
		f.warn("the provisioning file from %s does not decrypt with this device's key", server)
		return nil, false
	}
	if len(t.ca) == 0 {
		f.warn("no CA certificate on the ESP, not verifying who signed the provisioning file")
		content, _, err := cms.VerifySignature(signed)
		if err != nil {
			f.warn("the provisioning file from %s is not a signed file", server)
			return nil, false
		}
		return content, true
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(t.ca)
	content, signer, err := cms.Verify(signed, roots, time.Now())
	if err != nil {
		f.warn("the provisioning file from %s is not signed by a certificate from provision/ca.pem", server)
		return nil, false
	}
	if subject := signer.Subject.String(); subject != "CN="+cms.SignerCN {
		f.warn("the provisioning file from %s is signed by %s, not %s", server, subject, cms.SignerCN)
		return nil, false
	}
	return content, true
}

func inSessionOf(cgroup []byte, uid string) bool {
	return strings.Contains(string(cgroup), "/user-"+uid+".slice/")
}

func detachArgs(exe, user string, getenv func(string) string) []string {
	args := []string{"--unit=provision-fetch", "--collect", "--quiet"}
	for _, k := range []string{"PATH", "PROVISION_ESP", "PROVISION_TIME_WAIT", "PROVISION_MDNS_TIMEOUT"} {
		if v := getenv(k); v != "" {
			args = append(args, "--setenv="+k+"="+v)
		}
	}
	return append(args, exe, "fetch", user)
}

func (f *Fetcher) detach(user string) int {
	exe, err := os.Executable()
	if err == nil {
		cmd := exec.Command("systemd-run", detachArgs(exe, user, f.Getenv)...)
		cmd.Stdout = f.Stdout
		cmd.Stderr = f.Stderr
		err = cmd.Run()
	}
	if err != nil {
		f.warn("could not run outside the sessions of %s: %v", user, err)
		return 1
	}
	f.say("running as provision-fetch.service, which may end the sessions of %s: journalctl -u provision-fetch", user)
	return 0
}

func (f *Fetcher) Run(user string) int {
	if info, err := os.Stat("/home/" + user); user == "" || err != nil || !info.IsDir() {
		f.warn("no image user home, nothing to provision")
		return 0
	}
	t := f.trust()
	if len(t.cert) == 0 || len(t.key) == 0 {
		f.say("no client certificate on the ESP, nothing to fetch")
		return 0
	}
	if account, err := osuser.Lookup(user); err == nil {
		cgroup, _ := os.ReadFile("/proc/self/cgroup")
		if inSessionOf(cgroup, account.Uid) {
			return f.detach(user)
		}
	}
	f.waitForClock()
	server := f.discover()
	if server == "" {
		f.warn("no provisioning server on mDNS and no default gateway")
		return 1
	}
	body, err := f.get(server, t)
	if err != nil {
		f.warn("could not fetch %s/cgi-bin/provision: %v", server, err)
		return 1
	}
	if len(body) == 0 {
		f.say("%s has nothing for this device", server)
		return 0
	}
	content, ok := f.open(body, server, t)
	if !ok {
		return 1
	}
	cfg, err := devicefile.Parse(content)
	if err != nil {
		fmt.Fprintf(f.Stderr, "provision: invalid provisioning file: %v\n", err)
		return 1
	}
	a := &apply.Applier{Stdout: f.Stdout, Stderr: f.Stderr}
	if !a.Apply(cfg, user) {
		return 1
	}
	return 0
}
