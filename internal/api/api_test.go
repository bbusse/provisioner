package api

import (
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbusse/provisioner/internal/ca"
	"github.com/bbusse/provisioner/internal/ca/catest"
	"github.com/bbusse/provisioner/internal/jobs"
	"github.com/bbusse/provisioner/internal/settings"
	"github.com/bbusse/provisioner/internal/store"
)

func leaf(t *testing.T, c *catest.CA, cn string, usage x509.ExtKeyUsage, dir string) (string, string) {
	t.Helper()
	certPath, keyPath, err := c.Issue(cn, usage, dir)
	if err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestAPI(t *testing.T) {
	dir := t.TempDir()
	fake := catest.New()
	issuer := fake.Named("example-ca")
	caPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, []byte(issuer.PEM()), 0o600)
	serverCert, serverKey := leaf(t, issuer, "provisioner", x509.ExtKeyUsageServerAuth, dir)
	adminCert, adminKey := leaf(t, issuer, "admin-test", x509.ExtKeyUsageClientAuth, dir)
	devCert, devKey := leaf(t, issuer, "dev9", x509.ExtKeyUsageClientAuth, dir)
	strangerCert, strangerKey := leaf(t, catest.NewCA("other", time.Now().Add(time.Hour)), "admin-test2", x509.ExtKeyUsageClientAuth, dir)

	s := &settings.Settings{
		CAName: "example-ca", CertDays: 397, KeyType: "ec",
		WGInstance: "example", WGKeepalive: 25, K8sParentCA: "example-root", K8sCADays: 3650,
		CertsDir: filepath.Join(dir, "data", "certs"), PlainDir: filepath.Join(dir, "data", "plain"),
		DevicesDir: filepath.Join(dir, "data", "devices"),
		TLSCert:    serverCert, TLSKey: serverKey, ClientCA: caPath, Admins: []string{"admin-test"},
	}
	newJobs := func(s *settings.Settings, log func(string, ...any)) *jobs.Jobs {
		j := jobs.New(s, log)
		j.Backend = func() (ca.Backend, error) { return fake, nil }
		return j
	}
	server := &Server{Settings: s, NewJobs: newJobs, Logger: log.New(io.Discard, "", 0)}
	tlsConfig, err := server.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(server.Handler())
	ts.TLS = tlsConfig
	ts.StartTLS()
	defer ts.Close()

	admin, err := NewClient(ts.URL, adminCert, adminKey, caPath)
	if err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := admin.Do("POST", "/v1/signer", nil, &resp); err != nil || resp.Error != "" {
		t.Fatalf("signer: %v %v", err, resp)
	}
	resp = Response{}
	if err := admin.Do("POST", "/v1/devices/dev/config", map[string]any{"user": "bob", "no_wg": true}, &resp); err != nil || resp.Error != "" {
		t.Fatalf("config: %v %+v", err, resp)
	}
	if !strings.Contains(strings.Join(resp.Log, "\n"), "provision-add-trust DISK dev") {
		t.Errorf("log %v", resp.Log)
	}
	if strings.Contains(strings.Join(resp.Log, "\n"), "PRIVATE KEY") || strings.Contains(strings.Join(resp.Log, "\n"), "hostname") {
		t.Errorf("the response carries file contents: %v", resp.Log)
	}
	var devices []Device
	if err := admin.Do("GET", "/v1/devices", nil, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0] != (Device{Name: "dev", Plain: true, Sealed: true, Cert: true}) {
		t.Errorf("devices %+v", devices)
	}
	st := &store.Store{Certs: s.CertsDir, Plain: s.PlainDir, Devices: s.DevicesDir}
	if _, err := os.Stat(st.SealedPath("dev")); err != nil {
		t.Error(err)
	}

	resp = Response{}
	admin.Do("POST", "/v1/devices/dev/config", map[string]any{"no_wg": true}, &resp)
	if !strings.Contains(resp.Error, "exists") {
		t.Errorf("a second config: %+v", resp)
	}
	raw, err := admin.HTTP.Post(ts.URL+"/v1/devices/dev2/config", "application/json", strings.NewReader(`{"frobnicate": 1}`))
	if err != nil || raw.StatusCode != http.StatusBadRequest {
		t.Errorf("an unknown field: %v %v", err, raw.Status)
	}
	raw, err = admin.HTTP.Get(ts.URL + "/v1/devices/dev")
	if err != nil || raw.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET on a job: %v %v", err, raw.Status)
	}

	dev, _ := NewClient(ts.URL, devCert, devKey, caPath)
	resp = Response{}
	if err := dev.Do("POST", "/v1/signer", nil, &resp); err != nil || resp.Error != "not an admin" {
		t.Errorf("a device certificate: %v %+v", err, resp)
	}
	stranger, _ := NewClient(ts.URL, strangerCert, strangerKey, caPath)
	if err := stranger.Do("GET", "/v1/devices", nil, &devices); err == nil {
		t.Error("a certificate from another CA gets through")
	}
	anonymous, _ := NewClient(ts.URL, "", "", caPath)
	if err := anonymous.Do("GET", "/healthz", nil, &devices); err == nil {
		t.Error("no client certificate gets through")
	}
}
