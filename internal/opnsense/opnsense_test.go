package opnsense

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/bbusse/provisioner/internal/ca"
	"github.com/bbusse/provisioner/internal/opnsense/opnsensetest"
	"github.com/bbusse/provisioner/internal/settings"
)

func start(t *testing.T) (*opnsensetest.Fake, *Client) {
	t.Helper()
	fake := opnsensetest.Start()
	t.Cleanup(fake.Close)
	_, port, _ := net.SplitHostPort(fake.Addr())
	c, err := New("https://pathfinder-1.e2m:8888", "pathfinder-1.e2m:8888:127.0.0.1:"+port, fake.Pin(), fake.WriteKeyFile(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	return fake, c
}

func csr(t *testing.T, cn string) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func parse(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatalf("no PEM: %q", s)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIsABackend(t *testing.T) {
	var _ ca.Backend = &Client{}
}

func TestCA(t *testing.T) {
	fake, c := start(t)
	got, err := c.CA("e2m-0")
	if err != nil || got != fake.CA("e2m-0").PEM() {
		t.Errorf("%v", err)
	}
	if _, err := c.CA("nope"); !errors.Is(err, ca.ErrNotFound) {
		t.Errorf("%v", err)
	}
}

func TestSignMapsProfiles(t *testing.T) {
	_, c := start(t)
	for _, tc := range []struct {
		profile ca.Profile
		check   func(*x509.Certificate) bool
	}{
		{ca.ProfileClient, func(x *x509.Certificate) bool { return x.ExtKeyUsage[0] == x509.ExtKeyUsageClientAuth }},
		{ca.ProfileServer, func(x *x509.Certificate) bool {
			return x.ExtKeyUsage[0] == x509.ExtKeyUsageServerAuth && x.DNSNames[0] == "web-server" && x.IPAddresses[0].String() == "10.0.0.7"
		}},
		{ca.ProfileCA, func(x *x509.Certificate) bool { return x.IsCA }},
	} {
		name := "web-" + string(tc.profile)
		if ok, _ := c.HasCert(name); ok {
			t.Errorf("%s exists before", name)
		}
		signed, err := c.Sign("e2m-hqb", ca.SignRequest{Name: name, Profile: tc.profile, CSR: csr(t, name), Days: 30,
			DNS: []string{name}, IPs: []string{"10.0.0.7"}})
		if err != nil {
			t.Fatalf("%s: %v", tc.profile, err)
		}
		if x := parse(t, signed.PEM); !tc.check(x) || x.Subject.CommonName != name || !strings.HasPrefix(signed.ID, "cert-") {
			t.Errorf("%s: %+v", tc.profile, x)
		}
		if ok, err := c.HasCert(name); !ok || err != nil {
			t.Errorf("%s is not there: %v", name, err)
		}
	}
	if _, err := c.Sign("e2m-hqb", ca.SignRequest{Name: "x", Profile: "usr_cert", CSR: csr(t, "x"), Days: 1}); err == nil {
		t.Error("an unknown profile")
	}
	if _, err := c.Sign("nope", ca.SignRequest{Name: "x", Profile: ca.ProfileClient, CSR: csr(t, "x"), Days: 1}); !errors.Is(err, ca.ErrNotFound) {
		t.Errorf("an unknown CA: %v", err)
	}
}

func TestAddPeer(t *testing.T) {
	fake, c := start(t)
	peer, err := c.AddPeer("e2m", "dev", ca.PeerRequest{PublicKey: "devpub=", PresharedKey: "psk="})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(peer.Address, ",") != "10.99.0.4/32" || peer.Endpoint != "vpn.example.org:51820" ||
		strings.Join(peer.AllowedIPs, ",") != "10.99.0.0/24,fd99::/64" || peer.PublicKey != "serverpub=" {
		t.Errorf("%+v", peer)
	}
	p := fake.Peers[0]
	if p.Name != "dev" || p.PubKey != "devpub=" || p.PSK != "psk=" || p.Address != "10.99.0.4/32" || p.Server != "wg-uuid" {
		t.Errorf("%+v", p)
	}
	if fake.Requests[len(fake.Requests)-1] != "POST wireguard/service/reconfigure" {
		t.Errorf("no reconfigure: %v", fake.Requests)
	}
	if _, err := c.AddPeer("e2m", "dev", ca.PeerRequest{PublicKey: "x"}); !errors.Is(err, ca.ErrExists) {
		t.Errorf("a second peer: %v", err)
	}
	if _, err := c.AddPeer("nope", "dev2", ca.PeerRequest{PublicKey: "x"}); !errors.Is(err, ca.ErrNotFound) {
		t.Errorf("an unknown instance: %v", err)
	}
}

func TestPin(t *testing.T) {
	fake := opnsensetest.Start()
	defer fake.Close()
	_, port, _ := net.SplitHostPort(fake.Addr())
	c, err := New("https://pathfinder-1.e2m:8888", "pathfinder-1.e2m:8888:127.0.0.1:"+port,
		"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", fake.WriteKeyFile(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CA("e2m-hqb"); err == nil || !strings.Contains(err.Error(), "OPNSENSE_PIN") {
		t.Errorf("%v", err)
	}
	if _, err := New("https://x", "", "", "/nonexistent"); err == nil {
		t.Error("no pin")
	}
}

func TestRegistered(t *testing.T) {
	fake := opnsensetest.Start()
	defer fake.Close()
	_, port, _ := net.SplitHostPort(fake.Addr())
	b, err := ca.Open("opnsense", settings.Env{
		"OPNSENSE_URL":          "https://pathfinder-1.e2m:8888",
		"OPNSENSE_CONNECT_TO":   "pathfinder-1.e2m:8888:127.0.0.1:" + port,
		"OPNSENSE_PIN":          fake.Pin(),
		"OPNSENSE_API_KEY_FILE": fake.WriteKeyFile(t.TempDir()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.CA("e2m-hqb"); err != nil || got != fake.CA("e2m-hqb").PEM() {
		t.Errorf("%v", err)
	}
	if _, err := ca.Open("", settings.Env{}); err == nil || !strings.Contains(err.Error(), "one of: opnsense") {
		t.Errorf("%v", err)
	}
	if _, err := ca.Open("vault", settings.Env{}); err == nil || !strings.Contains(err.Error(), "no CA backend vault") {
		t.Errorf("%v", err)
	}
}
