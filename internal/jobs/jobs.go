package jobs

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bbusse/provisioner/internal/ca"
	"github.com/bbusse/provisioner/internal/pki"
	"github.com/bbusse/provisioner/internal/settings"
	"github.com/bbusse/provisioner/internal/store"
)

type Jobs struct {
	S       *settings.Settings
	Store   *store.Store
	Log     func(format string, args ...any)
	Backend func() (ca.Backend, error)
	backend ca.Backend
}

func New(s *settings.Settings, log func(string, ...any)) *Jobs {
	j := &Jobs{
		S:     s,
		Store: &store.Store{Certs: s.CertsDir, Plain: s.PlainDir, Devices: s.DevicesDir},
		Log:   log,
	}
	j.Backend = func() (ca.Backend, error) {
		return ca.Open(s.CA, s.Env)
	}
	return j
}

func (j *Jobs) ca() (ca.Backend, error) {
	if j.backend != nil {
		return j.backend, nil
	}
	b, err := j.Backend()
	if err != nil {
		return nil, err
	}
	j.backend = b
	return b, nil
}

var reSANDNS = regexp.MustCompile(`^[A-Za-z0-9*]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

func (j *Jobs) issue(profile ca.Profile, name string, sans []string) error {
	dns := []string{name}
	var ips []string
	for _, san := range sans {
		if _, err := netip.ParseAddr(san); err == nil {
			ips = append(ips, san)
		} else if reSANDNS.MatchString(san) {
			dns = append(dns, san)
		} else {
			return fmt.Errorf("not a DNS name or IP address: %s", san)
		}
	}
	backend, err := j.ca()
	if err != nil {
		return err
	}
	caPEM, err := backend.CA(j.S.CAName)
	if err != nil {
		return err
	}
	caCert, err := pki.ParseCert([]byte(caPEM))
	if err != nil {
		return fmt.Errorf("%s: %w", j.S.CAName, err)
	}
	out := j.Store.CertDir(name)
	if err := store.PrivateDir(j.S.CertsDir, out); err != nil {
		return err
	}
	if err := store.WriteFile(filepath.Join(out, "ca.pem"), []byte(strings.TrimRight(caPEM, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	key, err := pki.GenerateKey(j.S.KeyType)
	if err != nil {
		return err
	}
	csr, err := pki.CSR(key, name)
	if err != nil {
		return err
	}
	signed, err := backend.Sign(j.S.CAName, ca.SignRequest{
		Name: name, Profile: profile, CSR: string(csr), Days: j.S.CertDays, DNS: dns, IPs: ips,
	})
	if err != nil {
		return err
	}
	cert, err := pki.ParseCert([]byte(signed.PEM))
	if err != nil {
		return err
	}
	usage := x509.ExtKeyUsageClientAuth
	if profile == ca.ProfileServer {
		usage = x509.ExtKeyUsageServerAuth
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return fmt.Errorf("the certificate for %s does not verify against %s", name, j.S.CAName)
	}
	if !pki.SamePublicKey(cert, key) {
		return fmt.Errorf("the certificate for %s is not for its key", name)
	}
	keyPEM, err := pki.KeyPEM(key)
	if err != nil {
		return err
	}
	if err := store.WriteFile(j.Store.KeyPath(name), keyPEM, 0o600); err != nil {
		return err
	}
	if err := store.WriteFile(j.Store.CertPath(name), pki.CertPEM(cert), 0o644); err != nil {
		return err
	}
	j.Log("%s signed by %s (cert %s)", name, j.S.CAName, signed.ID)
	j.Log("subject=CN=%s notAfter=%s DNS=%s IP=%s", name, cert.NotAfter.UTC().Format(time.RFC3339),
		strings.Join(cert.DNSNames, ","), joinIPs(cert))
	return nil
}

func joinIPs(cert *x509.Certificate) string {
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return strings.Join(ips, ",")
}

func (j *Jobs) Server(name string, sans []string) error {
	if err := store.CheckName(name); err != nil {
		return err
	}
	return j.issue(ca.ProfileServer, name, sans)
}

func (j *Jobs) Signer() error {
	if store.Exists(j.Store.CertPath(store.SignerName)) {
		return fmt.Errorf("%s has a signer already", j.Store.CertDir(store.SignerName))
	}
	return j.issue(ca.ProfileClient, store.SignerName, nil)
}

func (j *Jobs) deviceCert(name string) error {
	if j.Store.HasCert(name) {
		j.Log("%s has a client certificate, keeping it", name)
		return nil
	}
	return j.issue(ca.ProfileClient, name, nil)
}

func (j *Jobs) deviceDone(name string) {
	j.Log("commit and push devices/%s.cms, routers pull it", name)
	j.Log("On the device image:\n  image-builder provision-add-trust DISK %s", name)
}

func checkDevice(name string) error {
	if err := store.CheckName(name); err != nil {
		return err
	}
	if name == store.SignerName {
		return fmt.Errorf("%s is the signer, not a device", name)
	}
	return nil
}

func (j *Jobs) Device(name string) error {
	if err := checkDevice(name); err != nil {
		return err
	}
	signer, err := j.Store.Signer()
	if err != nil {
		return err
	}
	if err := j.deviceCert(name); err != nil {
		return err
	}
	if err := j.wgPeer(name, j.Store.PlainPath(name)); err != nil {
		return err
	}
	if err := j.Store.CheckTOML(j.Store.PlainPath(name)); err != nil {
		return err
	}
	if err := j.Store.Seal(name, signer, j.Log); err != nil {
		return err
	}
	j.deviceDone(name)
	return nil
}

func (j *Jobs) Seal(names []string) error {
	signer, err := j.Store.Signer()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		matches, _ := filepath.Glob(filepath.Join(j.Store.Plain, "*.toml"))
		for _, m := range matches {
			names = append(names, strings.TrimSuffix(filepath.Base(m), ".toml"))
		}
		if len(names) == 0 {
			return fmt.Errorf("nothing to seal in %s", j.Store.Plain)
		}
	}
	for _, name := range names {
		if err := store.CheckName(name); err != nil {
			return err
		}
		if err := j.Store.Seal(name, signer, j.Log); err != nil {
			return err
		}
	}
	return nil
}

func (j *Jobs) Open(name string) error {
	if err := store.CheckName(name); err != nil {
		return err
	}
	signer, err := j.Store.Signer()
	if err != nil {
		return err
	}
	return j.Store.Open(name, signer, j.Log)
}

func appendText(path, text string, mode os.FileMode) error {
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return store.WriteFile(path, append(current, text...), mode)
}

func (j *Jobs) wgPeer(name, file string) error {
	if text, err := os.ReadFile(file); err == nil && hasSection(string(text), reWGSection) {
		j.Log("%s has a [wg] section, keeping it", file)
		return nil
	}
	backend, err := j.ca()
	if err != nil {
		return err
	}
	private, public, psk, err := pki.WireGuardKeys()
	if err != nil {
		return err
	}
	peer, err := backend.AddPeer(j.S.WGInstance, name, ca.PeerRequest{PublicKey: public, PresharedKey: psk})
	if errors.Is(err, ca.ErrExists) {
		return fmt.Errorf("%s already has a peer named %s but %s has no [wg]; delete the peer or add [wg] by hand", j.S.WGInstance, name, file)
	}
	if err != nil {
		return err
	}
	if len(peer.Address) == 0 || peer.PublicKey == "" || peer.Endpoint == "" || len(peer.AllowedIPs) == 0 {
		return fmt.Errorf("peer %s was added on %s without an address, public key, endpoint or allowed IPs", peer.ID, backend)
	}

	if err := store.PrivateDir(j.Store.Plain); err != nil {
		return err
	}
	text := ""
	if _, err := os.Stat(file); err != nil {
		text = fmt.Sprintf("[system]\nhostname = \"%s\"\n", name)
	}
	text += fmt.Sprintf("\n[wg]\nprivate_key = \"%s\"\naddress = %s\n\n[[wg.peer]]\npublic_key = \"%s\"\npreshared_key = \"%s\"\nendpoint = \"%s\"\nallowed_ips = %s\npersistent_keepalive = %d\n",
		private, tomlList(peer.Address), peer.PublicKey, psk, peer.Endpoint, tomlList(peer.AllowedIPs), j.S.WGKeepalive)
	if err := appendText(file, text, 0o600); err != nil {
		return fmt.Errorf("peer %s was added on %s but %s could not be written", peer.ID, backend, file)
	}
	if err := j.addRole(file, "wg"); err != nil {
		return fmt.Errorf("peer %s was added on %s but %s could not be written: %w", peer.ID, backend, file, err)
	}
	j.Log("%s is peer %s of %s at %s", name, peer.ID, j.S.WGInstance, strings.Join(peer.Address, ","))
	return nil
}

func (j *Jobs) addRole(file, role string) error {
	text, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	out, err := addRole(string(text), role)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	return store.WriteFile(file, []byte(out), 0o600)
}
