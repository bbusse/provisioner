package catest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/bbusse/provisioner/internal/ca"
)

type CA struct {
	Name string
	Cert *x509.Certificate
	Key  crypto.Signer
}

func (c *CA) PEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}))
}

func NewCA(name string, notAfter time.Time) *CA {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	cert, _ := x509.ParseCertificate(der)
	return &CA{Name: name, Cert: cert, Key: key}
}

func (c *CA) Issue(cn string, usage x509.ExtKeyUsage, dir string) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, key.Public(), c.Key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, cn+".pem")
	keyPath := filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

type Peer struct {
	Instance, Name, PublicKey, PresharedKey string
	Address                                 []string
}

type Fake struct {
	CAs      []*CA
	Certs    map[string]*x509.Certificate
	Peers    []Peer
	Requests []string
	mu       sync.Mutex
	next     int
}

func New() *Fake {
	f := &Fake{Certs: map[string]*x509.Certificate{}}
	for _, name := range []string{"e2m-hqb", "e2m-0"} {
		f.CAs = append(f.CAs, NewCA(name, time.Now().AddDate(2, 0, 0)))
	}
	return f
}

func (f *Fake) String() string { return "the fake CA" }

func (f *Fake) Named(name string) *CA {
	for _, c := range f.CAs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (f *Fake) CA(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Requests = append(f.Requests, "ca "+name)
	c := f.Named(name)
	if c == nil {
		return "", fmt.Errorf("no CA named %s: %w", name, ca.ErrNotFound)
	}
	return c.PEM(), nil
}

func (f *Fake) HasCert(name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Requests = append(f.Requests, "cert "+name)
	_, ok := f.Certs[name]
	return ok, nil
}

func (f *Fake) Sign(caName string, r ca.SignRequest) (*ca.Signed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Requests = append(f.Requests, "sign "+r.Name)
	parent := f.Named(caName)
	if parent == nil {
		return nil, fmt.Errorf("no CA named %s: %w", caName, ca.ErrNotFound)
	}
	block, _ := pem.Decode([]byte(r.CSR))
	if block == nil {
		return nil, fmt.Errorf("no CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(0, 0, r.Days),
	}
	switch r.Profile {
	case ca.ProfileClient:
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case ca.ProfileServer:
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = r.DNS
		for _, ip := range r.IPs {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
		}
	case ca.ProfileCA:
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.Cert, csr.PublicKey, parent.Key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	f.Certs[r.Name] = cert
	f.next++
	return &ca.Signed{
		ID:  "cert-" + strconv.Itoa(f.next),
		PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}, nil
}

func (f *Fake) AddPeer(instance, name string, r ca.PeerRequest) (*ca.Peer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Requests = append(f.Requests, "peer "+name)
	for _, p := range f.Peers {
		if p.Instance == instance && p.Name == name {
			return nil, fmt.Errorf("%s already has a peer named %s: %w", instance, name, ca.ErrExists)
		}
	}
	p := Peer{Instance: instance, Name: name, PublicKey: r.PublicKey, PresharedKey: r.PresharedKey,
		Address: []string{fmt.Sprintf("10.99.0.%d/32", 4+len(f.Peers))}}
	f.Peers = append(f.Peers, p)
	f.next++
	return &ca.Peer{
		ID:         "peer-" + strconv.Itoa(f.next),
		Address:    p.Address,
		PublicKey:  "serverpub=",
		Endpoint:   "vpn.example.org:51820",
		AllowedIPs: []string{"10.99.0.0/24", "fd99::/64"},
	}, nil
}
