package provide

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var serial int64

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, tmpl *x509.Certificate, parent *ca, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	p, signer := tmpl, crypto.Signer(key)
	if parent != nil {
		p, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newCA(t *testing.T, name string, parent *ca) *ca {
	t.Helper()
	key := newKey(t)
	c := sign(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, parent, key)
	return &ca{c, key}
}

func (a *ca) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	c := sign(t, tmpl, a, key)
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type testEnv struct {
	ca   *ca
	dir  string
	opts options
	url  string
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	root := t.TempDir()
	e := &testEnv{ca: newCA(t, "test-ca", nil), dir: filepath.Join(root, "provision")}
	if err := os.Mkdir(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e.opts = options{
		cert: filepath.Join(root, "server.pem"),
		key:  filepath.Join(root, "server.key"),
		ca:   filepath.Join(e.dir, "ca.pem"),
		dir:  e.dir,
	}
	server := e.ca.issue(t, "test-provisioner", x509.ExtKeyUsageServerAuth)
	keyDER, err := x509.MarshalPKCS8PrivateKey(server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.opts.cert, certPEM(server.Leaf))
	writeFile(t, e.opts.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	writeFile(t, e.opts.ca, certPEM(e.ca.cert))

	srv, _, err := newServer(e.opts)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	e.url = "https://" + ln.Addr().String()
	return e
}

func (e *testEnv) do(t *testing.T, method, path string, cert *tls.Certificate) (*http.Response, string, error) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.cert)
	cfg := &tls.Config{RootCAs: roots}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
	req, err := http.NewRequest(method, e.url+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body), nil
}

func client(t *testing.T, a *ca, cn string) *tls.Certificate {
	t.Helper()
	c := a.issue(t, cn, x509.ExtKeyUsageClientAuth)
	return &c
}

func (e *testEnv) get(t *testing.T, cert *tls.Certificate) (*http.Response, string) {
	t.Helper()
	resp, body, err := e.do(t, http.MethodGet, "/cgi-bin/provision", cert)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func expect(t *testing.T, resp *http.Response, body string, status int, contentType, want string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("status %d, want %d", resp.StatusCode, status)
	}
	if contentType != "" && resp.Header.Get("Content-Type") != contentType {
		t.Errorf("Content-Type %q, want %q", resp.Header.Get("Content-Type"), contentType)
	}
	if body != want {
		t.Errorf("body %q, want %q", body, want)
	}
}

func TestServesOwnFile(t *testing.T) {
	e := setup(t)
	writeFile(t, filepath.Join(e.dir, "testdev.toml"), []byte("hostname = \"testdev\"\n"))
	writeFile(t, filepath.Join(e.dir, "otherdev.cms"), []byte("other"))
	resp, body := e.get(t, client(t, e.ca, "testdev"))
	expect(t, resp, body, http.StatusOK, "application/toml", "hostname = \"testdev\"\n")
}

func TestPrefersCMS(t *testing.T) {
	e := setup(t)
	writeFile(t, filepath.Join(e.dir, "testdev.toml"), []byte("plain"))
	writeFile(t, filepath.Join(e.dir, "testdev.cms"), []byte("sealed"))
	resp, body := e.get(t, client(t, e.ca, "testdev"))
	expect(t, resp, body, http.StatusOK, "application/cms", "sealed")
}

func TestDirectoryIsNoFile(t *testing.T) {
	e := setup(t)
	if err := os.Mkdir(filepath.Join(e.dir, "testdev.cms"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.dir, "testdev.toml"), []byte("plain"))
	resp, body := e.get(t, client(t, e.ca, "testdev"))
	expect(t, resp, body, http.StatusOK, "application/toml", "plain")
}

func TestNoFile(t *testing.T) {
	e := setup(t)
	resp, body := e.get(t, client(t, e.ca, "testdev"))
	expect(t, resp, body, http.StatusOK, "application/toml", "")
}

func TestHead(t *testing.T) {
	e := setup(t)
	writeFile(t, filepath.Join(e.dir, "testdev.cms"), []byte("sealed"))
	resp, body, err := e.do(t, http.MethodHead, "/cgi-bin/provision", client(t, e.ca, "testdev"))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, resp, body, http.StatusOK, "application/cms", "")
}

func TestRefusedClients(t *testing.T) {
	e := setup(t)
	writeFile(t, filepath.Join(e.dir, "testdev.cms"), []byte("sealed"))
	other := newCA(t, "test-ca", nil)
	intermediate := newCA(t, "intermediate", e.ca)
	viaIntermediate := client(t, intermediate, "testdev")
	viaIntermediate.Certificate = append(viaIntermediate.Certificate, intermediate.cert.Raw)
	serverOnly := e.ca.issue(t, "testdev", x509.ExtKeyUsageServerAuth)
	cases := map[string]*tls.Certificate{
		"no client certificate": nil,
		"another CA":            client(t, other, "testdev"),
		"intermediate":          viaIntermediate,
		"serverAuth only":       &serverOnly,
	}
	for name, cert := range cases {
		t.Run(name, func(t *testing.T) {
			resp, body, err := e.do(t, http.MethodGet, "/cgi-bin/provision", cert)
			if err == nil {
				t.Fatalf("request succeeded: %d %q", resp.StatusCode, body)
			}
		})
	}
}

func TestBadCN(t *testing.T) {
	e := setup(t)
	writeFile(t, filepath.Join(e.dir, "testdev.toml"), []byte("plain"))
	writeFile(t, filepath.Join(e.dir, ".hidden.toml"), []byte("hidden"))
	for _, cn := range []string{"../provision/testdev", ".hidden", "", ".", "..", "test dev", "testdev/", "testdev\x00", "tëstdev"} {
		t.Run(cn, func(t *testing.T) {
			resp, body := e.get(t, client(t, e.ca, cn))
			expect(t, resp, body, http.StatusForbidden, "", "")
		})
	}
}

func TestWrongPath(t *testing.T) {
	e := setup(t)
	writeFile(t, filepath.Join(e.dir, "testdev.toml"), []byte("plain"))
	dev := client(t, e.ca, "testdev")
	for _, path := range []string{"/", "/cgi-bin/", "/cgi-bin/provision/", "/cgi-bin/provision/x", "/cgi-bin/other", "/testdev.toml", "/provision/testdev.toml"} {
		t.Run(path, func(t *testing.T) {
			resp, _, err := e.do(t, http.MethodGet, path, dev)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status %d, want 404", resp.StatusCode)
			}
		})
	}
	resp, _, err := e.do(t, http.MethodPost, "/cgi-bin/provision", dev)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", resp.StatusCode)
	}
}

func TestQueryIgnored(t *testing.T) {
	e := setup(t)
	writeFile(t, filepath.Join(e.dir, "testdev.toml"), []byte("plain"))
	resp, body, err := e.do(t, http.MethodGet, "/cgi-bin/provision?cn=otherdev", client(t, e.ca, "testdev"))
	if err != nil {
		t.Fatal(err)
	}
	expect(t, resp, body, http.StatusOK, "application/toml", "plain")
}

func TestReloadsCA(t *testing.T) {
	e := setup(t)
	writeFile(t, filepath.Join(e.dir, "testdev.cms"), []byte("sealed"))
	next := newCA(t, "test-ca-next", nil)
	dev := client(t, next, "testdev")
	if _, _, err := e.do(t, http.MethodGet, "/cgi-bin/provision", dev); err == nil {
		t.Fatal("certificate from the next CA accepted before the reload")
	}

	writeFile(t, e.opts.ca, append(certPEM(e.ca.cert), certPEM(next.cert)...))
	resp, body := e.get(t, dev)
	expect(t, resp, body, http.StatusOK, "application/cms", "sealed")

	writeFile(t, e.opts.ca, []byte("garbage"))
	resp, body = e.get(t, dev)
	expect(t, resp, body, http.StatusOK, "application/cms", "sealed")

	writeFile(t, e.opts.ca, certPEM(e.ca.cert))
	if _, _, err := e.do(t, http.MethodGet, "/cgi-bin/provision", dev); err == nil {
		t.Fatal("certificate from the next CA accepted after it was removed")
	}
}

func TestReloadOnSignal(t *testing.T) {
	e := setup(t)
	c := &certs{certFile: e.opts.cert, keyFile: e.opts.key, caFile: e.opts.ca}
	if err := c.reload(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.opts.ca, []byte("garbage"))
	if err := c.reload(); err == nil {
		t.Fatal("reload with a broken CA succeeded")
	}
	if cfg, _ := c.config(nil); cfg == nil {
		t.Fatal("no configuration kept after a failed reload")
	}
}

func TestMissingFilesAtStart(t *testing.T) {
	dir := t.TempDir()
	_, _, err := newServer(options{
		cert: filepath.Join(dir, "server.pem"),
		key:  filepath.Join(dir, "server.key"),
		ca:   filepath.Join(dir, "ca.pem"),
		dir:  dir,
	})
	if err == nil {
		t.Fatal("started without certificates")
	}
}
