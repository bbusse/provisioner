package jobs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bbusse/provisioner/internal/store"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var reK8sFlux = regexp.MustCompile(`^\[k8s\.flux\][ \t]*$`)

// ScanHostKey reads the key an SSH server shows, the one a Go SSH client
// like Flux's negotiates
var ScanHostKey = func(addr string) (ssh.PublicKey, error) {
	var key ssh.PublicKey
	shown := errors.New("shown")
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _, _, err = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User: "git",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return shown
		},
	})
	if key == nil {
		return nil, fmt.Errorf("%s shows no host key: %w", addr, err)
	}
	return key, nil
}

func fluxDir(certs, cluster string) string {
	return filepath.Join(certs, "k8s-"+cluster, "flux")
}

// fluxSection is the [k8s.flux] table of a master of cluster, empty while
// the cluster has no deploy key
func fluxSection(certs, cluster string) (string, error) {
	dir := fluxDir(certs, cluster)
	if !store.Exists(filepath.Join(dir, "identity")) {
		return "", nil
	}
	var b strings.Builder
	b.WriteString("\n[k8s.flux]\n")
	for _, f := range []string{"identity", "known_hosts"} {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s = \"\"\"\n%s\n\"\"\"\n", f, strings.TrimRight(string(data), "\n"))
	}
	return b.String(), nil
}

var reTableHeader = regexp.MustCompile(`^\[\[?[A-Za-z0-9_.-]+\]\]?[ \t]*$`)

// dropFlux removes a [k8s.flux] table from a device file's text. Its
// values span lines, known_hosts lines start with [, so only a header
// outside a multi-line string ends it
func dropFlux(text string) string {
	var out []string
	in, quoted := false, false
	for _, l := range strings.Split(text, "\n") {
		if !quoted && reTableHeader.MatchString(l) {
			in = reK8sFlux.MatchString(l)
		}
		if strings.Count(l, `"""`)%2 == 1 {
			quoted = !quoted
		}
		if !in {
			out = append(out, l)
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
}

// Flux gives cluster a deploy key for its Flux repository at an ssh:// URL,
// with the keys of the repository's host, and hands both to the cluster's
// masters. The repository takes the public key as a read-only deploy key.
// Run again, it keeps the key and takes the host's keys anew
func (j *Jobs) Flux(cluster, repo string) error {
	if err := store.CheckName(cluster); err != nil {
		return err
	}
	u, err := url.Parse(repo)
	if err != nil || u.Scheme != "ssh" || u.Hostname() == "" || u.User == nil {
		return fmt.Errorf("not an ssh://USER@HOST[:PORT]/PATH URL: %s", repo)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "22")
	}
	if _, err := os.Stat(filepath.Join(j.S.CertsDir, "k8s-"+cluster, "k8s.toml")); err != nil {
		return fmt.Errorf("no cluster %s, run cluster %s", cluster, cluster)
	}
	dir := fluxDir(j.S.CertsDir, cluster)
	keep := store.Exists(filepath.Join(dir, "identity"))

	var masters []string
	plains, _ := filepath.Glob(filepath.Join(j.Store.Plain, "*.toml"))
	for _, f := range plains {
		text, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if isK8sMaster(string(text), cluster) {
			masters = append(masters, strings.TrimSuffix(filepath.Base(f), ".toml"))
		}
	}
	signer, err := j.Store.Signer()
	if err != nil {
		return err
	}

	hostKey, err := ScanHostKey(addr)
	if err != nil {
		return err
	}
	if err := store.PrivateDir(j.S.CertsDir, dir); err != nil {
		return err
	}
	if !keep {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		block, err := ssh.MarshalPrivateKey(priv, "flux-"+cluster)
		if err != nil {
			return err
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return err
		}
		authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " flux-" + cluster + "\n"
		if err := store.WriteFile(filepath.Join(dir, "identity.pub"), []byte(authorized), 0o644); err != nil {
			return err
		}
		if err := store.WriteFile(filepath.Join(dir, "identity"), pem.EncodeToMemory(block), 0o600); err != nil {
			return err
		}
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, hostKey) + "\n"
	if err := store.WriteFile(filepath.Join(dir, "known_hosts"), []byte(line), 0o644); err != nil {
		return err
	}
	authorized, err := os.ReadFile(filepath.Join(dir, "identity.pub"))
	if err != nil {
		return err
	}
	if keep {
		j.Log("cluster %s keeps its deploy key in %s, %s shows %s", cluster, dir, addr, hostKey.Type())
	} else {
		j.Log("deploy key for cluster %s in %s, %s shows %s", cluster, dir, addr, hostKey.Type())
	}

	section, err := fluxSection(j.S.CertsDir, cluster)
	if err != nil {
		return err
	}
	for _, device := range masters {
		path := j.Store.PlainPath(device)
		text, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out := dropFlux(string(text)) + section
		if err := j.writeChecked(device, out); err != nil {
			return fmt.Errorf("could not add the deploy key to %s: %w", path, err)
		}
		j.Log("%s carries the deploy key", device)
		if err := j.Store.Seal(device, signer, j.Log); err != nil {
			return err
		}
	}
	if len(masters) == 0 {
		j.Log("cluster %s has no master in %s yet, k8s DEVICE %s master adds the key", cluster, j.Store.Plain, cluster)
	}
	j.Log("add this read-only deploy key to %s:\n  %s", repo, strings.TrimSpace(string(authorized)))
	return nil
}

// writeChecked writes a device's plain file once its new text parses
func (j *Jobs) writeChecked(device, text string) error {
	work, err := os.MkdirTemp(j.Store.Plain, ".edit.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	candidate := filepath.Join(work, device+".toml")
	if err := os.WriteFile(candidate, []byte(text), 0o600); err != nil {
		return err
	}
	if err := j.Store.CheckTOML(candidate); err != nil {
		return err
	}
	return store.WriteFile(j.Store.PlainPath(device), []byte(text), 0o600)
}
