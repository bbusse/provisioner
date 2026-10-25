package jobs

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/bbusse/provisioner/internal/ca"
	"github.com/bbusse/provisioner/internal/ca/catest"
	"github.com/bbusse/provisioner/internal/cms"
	"github.com/bbusse/provisioner/internal/pki"
	"github.com/bbusse/provisioner/internal/settings"
	"github.com/bbusse/provisioner/internal/store"
)

type env struct {
	t    *testing.T
	dir  string
	fake *catest.Fake
	j    *Jobs
	log  []string
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	fake := catest.New()
	s := &settings.Settings{
		CAName:      "e2m-hqb",
		CertDays:    397,
		KeyType:     "ec",
		WGInstance:  "e2m",
		WGKeepalive: 25,
		K8sParentCA: "e2m-0",
		K8sCADays:   3650,
		CertsDir:    filepath.Join(dir, "certs"),
		PlainDir:    filepath.Join(dir, "plain"),
		DevicesDir:  filepath.Join(dir, "devices"),
	}
	e := &env{t: t, dir: dir, fake: fake}
	e.j = New(s, func(format string, args ...any) { e.log = append(e.log, fmt.Sprintf(format, args...)) })
	e.j.Backend = func() (ca.Backend, error) { return fake, nil }
	return e
}

func (e *env) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) logged(re string) bool {
	for _, l := range e.log {
		if regexp.MustCompile(re).MatchString(l) {
			return true
		}
	}
	return false
}

func (e *env) plain(name string) map[string]any {
	e.t.Helper()
	var cfg map[string]any
	if _, err := toml.DecodeFile(e.j.Store.PlainPath(name), &cfg); err != nil {
		e.t.Fatal(err)
	}
	return cfg
}

func (e *env) opens(name, as string) string {
	e.t.Helper()
	cert, err := pki.ReadCert(e.j.Store.CertPath(as))
	e.must(err)
	key, err := pki.ReadKey(e.j.Store.KeyPath(as))
	e.must(err)
	data, err := os.ReadFile(e.j.Store.SealedPath(name))
	e.must(err)
	roots := x509.NewCertPool()
	roots.AddCert(e.fake.Named("e2m-hqb").Cert)
	content, _, err := cms.Open(data, cert, key, roots, time.Now())
	e.must(err)
	return string(content)
}

func (e *env) signer() {
	e.t.Helper()
	e.must(e.j.Signer())
}

func (e *env) device(name string) {
	e.t.Helper()
	e.must(e.j.deviceCert(name))
	e.must(store.WriteFile(e.j.Store.PlainPath(name), []byte(fmt.Sprintf("[system]\nhostname = \"%s\"\n", name)), 0o600))
}

func TestSignerServerAndDevice(t *testing.T) {
	e := setup(t)
	e.signer()
	if err := e.j.Signer(); err == nil {
		t.Error("a second signer")
	}
	signer, err := pki.ReadCert(e.j.Store.CertPath(store.SignerName))
	e.must(err)
	if signer.Subject.CommonName != store.SignerName || signer.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("signer %v", signer.Subject)
	}

	e.must(e.j.Server("provisioner.e2m", []string{"10.0.0.7", "alt.e2m"}))
	server, err := pki.ReadCert(e.j.Store.CertPath("provisioner.e2m"))
	e.must(err)
	if strings.Join(server.DNSNames, ",") != "provisioner.e2m,alt.e2m" || server.IPAddresses[0].String() != "10.0.0.7" {
		t.Errorf("server SANs %v %v", server.DNSNames, server.IPAddresses)
	}
	if err := e.j.Server("bad", []string{"not a name"}); err == nil {
		t.Error("a bad SAN")
	}

	e.must(e.j.Device("dev"))
	cfg := e.plain("dev")
	system := cfg["system"].(map[string]any)
	wg := cfg["wg"].(map[string]any)
	if system["hostname"] != "dev" || fmt.Sprint(system["roles"]) != "[wg]" {
		t.Errorf("system %v", system)
	}
	peer := wg["peer"].([]map[string]any)[0]
	if fmt.Sprint(wg["address"]) != "[10.99.0.4/32]" || peer["endpoint"] != "vpn.example.org:51820" ||
		fmt.Sprint(peer["allowed_ips"]) != "[10.99.0.0/24 fd99::/64]" || peer["public_key"] != "serverpub=" {
		t.Errorf("wg %v", wg)
	}
	if len(e.fake.Peers) != 1 || e.fake.Peers[0].Name != "dev" || e.fake.Peers[0].PresharedKey != peer["preshared_key"] {
		t.Errorf("peers %v", e.fake.Peers)
	}
	plain, _ := os.ReadFile(e.j.Store.PlainPath("dev"))
	if e.opens("dev", "dev") != string(plain) || e.opens("dev", store.SignerName) != string(plain) {
		t.Error("the sealed file does not open to the plain one")
	}
	if !e.logged(`provision-add-trust DISK dev`) {
		t.Error(e.log)
	}

	e.log = nil
	e.must(e.j.Device("dev"))
	if !e.logged("has a client certificate, keeping it") || !e.logged(`has a \[wg\] section, keeping it`) || !e.logged("sealed already") {
		t.Error(e.log)
	}
	if len(e.fake.Peers) != 1 {
		t.Error("a second peer")
	}
	if err := e.j.Device(store.SignerName); err == nil {
		t.Error("the signer as a device")
	}
}

func TestDeviceRefusesASecondPeerOfTheSameName(t *testing.T) {
	e := setup(t)
	e.signer()
	e.fake.Peers = append(e.fake.Peers, catest.Peer{Instance: "e2m", Name: "dev"})
	if err := e.j.Device("dev"); err == nil || !strings.Contains(err.Error(), "already has a peer named dev") {
		t.Errorf("%v", err)
	}
}

func TestClusterThroughTheCA(t *testing.T) {
	e := setup(t)
	e.must(e.j.Cluster(ClusterOptions{Name: "e2m"}))
	d := filepath.Join(e.j.S.CertsDir, "k8s-e2m")
	ca, err := pki.ReadCert(filepath.Join(d, "ca.crt"))
	e.must(err)
	parent, err := pki.ReadCert(filepath.Join(d, "parent.pem"))
	e.must(err)
	if !ca.IsCA || ca.Subject.CommonName != "k8s-e2m" || !parent.Equal(e.fake.Named("e2m-0").Cert) {
		t.Errorf("cluster CA %v under %v", ca.Subject, parent.Subject)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parent)
	if _, err := ca.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Error(err)
	}
	var k8s struct {
		K8s map[string]string `toml:"k8s"`
	}
	_, err = toml.DecodeFile(filepath.Join(d, "k8s.toml"), &k8s)
	e.must(err)
	if k8s.K8s["ca_cert_hash"] != pki.CACertHash(ca) || k8s.K8s["endpoint"] != "e2m.k8s.internal:6443" ||
		k8s.K8s["endpoint_method"] != "mdns" || !regexp.MustCompile(`^[a-z0-9]{6}\.[a-z0-9]{16}$`).MatchString(k8s.K8s["token"]) {
		t.Errorf("k8s.toml %v", k8s.K8s)
	}
	info, _ := os.Stat(d)
	if info.Mode().Perm() != 0o700 {
		t.Errorf("mode %v", info.Mode())
	}
	if err := e.j.Cluster(ClusterOptions{Name: "e2m"}); err == nil {
		t.Error("a cluster made twice")
	}
	os.RemoveAll(d)
	if err := e.j.Cluster(ClusterOptions{Name: "e2m"}); err == nil || !strings.Contains(err.Error(), "has a certificate named k8s-e2m already") {
		t.Errorf("%v", err)
	}
	if _, err := os.Stat(d); err == nil {
		t.Error("left a cluster behind")
	}
}

func TestClusterWithALocalParentLivesNoLongerThanIt(t *testing.T) {
	e := setup(t)
	parent := catest.NewCA("parent", time.Now().Add(30*24*time.Hour+time.Hour))
	pdir := filepath.Join(e.dir, "parent")
	keyPEM, _ := pki.KeyPEM(parent.Key)
	e.must(store.WriteFile(filepath.Join(pdir, "ca.pem"), pki.CertPEM(parent.Cert), 0o600))
	e.must(store.WriteFile(filepath.Join(pdir, "ca.key"), keyPEM, 0o600))
	e.j.S.K8sParentDir = pdir
	e.must(e.j.Cluster(ClusterOptions{Name: "lab", Endpoint: "api.lab:7443", Method: "dns", PodCIDR: "10.32.0.0/16"}))
	ca, err := pki.ReadCert(filepath.Join(e.j.S.CertsDir, "k8s-lab", "ca.crt"))
	e.must(err)
	if ca.NotAfter.After(parent.Cert.NotAfter) {
		t.Errorf("the cluster CA outlives its parent: %v > %v", ca.NotAfter, parent.Cert.NotAfter)
	}
	if len(e.fake.Requests) != 0 {
		t.Errorf("asked the CA: %v", e.fake.Requests)
	}
	for _, o := range []ClusterOptions{{Name: "b", Endpoint: "no port"}, {Name: "b", Method: "m d"}, {Name: "b", PodCIDR: "x"}, {Name: "../b"}} {
		if err := e.j.Cluster(o); err == nil {
			t.Errorf("%+v", o)
		}
	}
}

func TestMastersAndClients(t *testing.T) {
	e := setup(t)
	e.signer()
	e.must(e.j.Cluster(ClusterOptions{Name: "e2m"}))
	e.must(e.j.Cluster(ClusterOptions{Name: "other"}))
	for _, name := range []string{"m1", "m2", "c1", "o1"} {
		e.device(name)
	}
	e.must(e.j.K8s("m1", "e2m", "master"))
	e.must(e.j.K8s("c1", "e2m", "client"))
	e.must(e.j.K8s("o1", "other", "master"))
	os.Remove(e.j.Store.PlainPath("m1"))
	e.must(e.j.K8s("m2", "e2m", "master"))

	k8s := func(name string) map[string]any {
		cfg := e.plain(name)
		return cfg["k8s"].(map[string]any)
	}
	e.must(e.j.Open("m1"))
	if k8s("m1")["bootstrap"] != true || k8s("o1")["bootstrap"] != true {
		t.Error("the first master of each cluster bootstraps")
	}
	if _, ok := k8s("m2")["bootstrap"]; ok {
		t.Error("the second master, whose peer is only sealed, bootstraps too")
	}
	if _, ok := k8s("c1")["pki"]; ok {
		t.Error("a client got the PKI")
	}
	pki := k8s("m2")["pki"].(map[string]any)
	key, _ := os.ReadFile(filepath.Join(e.j.S.CertsDir, "k8s-e2m", "ca.key"))
	if len(pki) != 8 || strings.TrimSpace(pki["ca_key"].(string)) != strings.TrimSpace(string(key)) {
		t.Errorf("master pki %d", len(pki))
	}
	if fmt.Sprint(e.plain("c1")["system"].(map[string]any)["roles"]) != "[k8s-client]" {
		t.Error(e.plain("c1"))
	}
	plain, _ := os.ReadFile(e.j.Store.PlainPath("m2"))
	if e.opens("m2", "m2") != string(plain) {
		t.Error("m2 is not sealed")
	}
	if err := e.j.K8s("c1", "e2m", "master"); err == nil || !strings.Contains(err.Error(), "has a [k8s] section already") {
		t.Errorf("%v", err)
	}
	if err := e.j.K8s("m2", "nocluster", "master"); err == nil {
		t.Error("no cluster")
	}
	entries, _ := os.ReadDir(e.j.Store.Plain)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Errorf("left %s in plain/", entry.Name())
		}
	}
}

func TestConfig(t *testing.T) {
	e := setup(t)
	e.signer()
	e.must(e.j.Cluster(ClusterOptions{Name: "e2m"}))
	key := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake "mue" \laptop`
	e.must(e.j.Config(ConfigOptions{Name: "dev", User: "mue", Roles: []string{"tv"}, Timezone: "Europe/Berlin",
		SSHKeys: []string{key}, K8s: "e2m:master"}))
	cfg := e.plain("dev")
	system := cfg["system"].(map[string]any)
	if system["user"] != "mue" || system["timezone"] != "Europe/Berlin" || fmt.Sprint(system["roles"]) != "[tv wg k8s-master]" {
		t.Errorf("system %v", system)
	}
	if cfg["ssh"].(map[string]any)["authorized_keys"].([]any)[0] != key {
		t.Errorf("ssh %v", cfg["ssh"])
	}
	if cfg["k8s"].(map[string]any)["bootstrap"] != true || cfg["wg"] == nil {
		t.Errorf("k8s or wg missing")
	}
	plain, _ := os.ReadFile(e.j.Store.PlainPath("dev"))
	if e.opens("dev", "dev") != string(plain) {
		t.Error("not sealed")
	}

	e.must(e.j.Config(ConfigOptions{Name: "bare", NoWG: true}))
	if got, _ := os.ReadFile(e.j.Store.PlainPath("bare")); string(got) != "[system]\nhostname = \"bare\"\n" {
		t.Errorf("%q", got)
	}

	if err := e.j.Config(ConfigOptions{Name: "dev", NoWG: true}); err == nil || !strings.Contains(err.Error(), "run device dev") {
		t.Errorf("%v", err)
	}
	requests := len(e.fake.Requests)
	for _, o := range []ConfigOptions{
		{Name: "x", User: "Mue"}, {Name: "x", Roles: []string{"../x"}}, {Name: "x", Timezone: "Europe/../x"},
		{Name: "x", SSHKeys: []string{"not-a-key"}}, {Name: "x", K8s: "nocluster:master"}, {Name: "x", K8s: "e2m:worker"},
		{Name: "../x"}, {Name: store.SignerName},
	} {
		if err := e.j.Config(o); err == nil {
			t.Errorf("%+v", o)
		}
		if _, err := os.Stat(e.j.Store.PlainPath(o.Name)); err == nil {
			t.Errorf("%+v wrote a file", o)
		}
	}
	if len(e.fake.Requests) != requests {
		t.Error("bad options reached the CA")
	}
}

func TestWithoutACA(t *testing.T) {
	e := setup(t)
	e.j = New(e.j.S, e.j.Log)
	if err := e.j.Signer(); err == nil || !strings.Contains(err.Error(), "set PROVISIONER_CA to the CA backend") {
		t.Errorf("%v", err)
	}
}

func TestAddRole(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"[ssh]\nx = 1\n", "[system]\nroles = [\"wg\"]\n\n[ssh]\nx = 1\n"},
		{"[system]\nhostname = \"a\"\n\n[ssh]\n", "[system]\nhostname = \"a\"\nroles = [\"wg\"]\n\n[ssh]\n"},
		{"[system]\nroles = [\"tv\", \"wg\"]\n", "[system]\nroles = [\"tv\", \"wg\"]\n"},
		{"[system]\nroles = [ \"tv\" ]\n", "[system]\nroles = [\"tv\", \"wg\"]\n"},
	} {
		got, err := addRole(c.in, "wg")
		if err != nil || got != c.want {
			t.Errorf("%q: %q, %v", c.in, got, err)
		}
	}
	if _, err := addRole("[system]\nroles = [\n\"tv\"]\n", "wg"); err == nil {
		t.Error("a multi-line roles list")
	}
}

func TestCfgProvisionReadsWhatGoWrites(t *testing.T) {
	script := os.Getenv("CFG_PROVISION")
	if script == "" {
		script = "../../../cfg-provision"
	}
	script = filepath.Join(script, "cfg-provision")
	if _, err := os.Stat(script); err != nil {
		t.Skip("no cfg-provision checkout, set CFG_PROVISION")
	}
	var openssl string
	for _, p := range []string{"/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "openssl"} {
		if path, err := exec.LookPath(p); err == nil {
			if out, err := exec.Command(path, "version").Output(); err == nil && strings.HasPrefix(string(out), "OpenSSL ") && !strings.HasPrefix(string(out), "OpenSSL 1.") {
				openssl = path
				break
			}
		}
	}
	if openssl == "" {
		t.Skip("no OpenSSL 3 or later")
	}
	e := setup(t)
	e.signer()
	e.must(e.j.Cluster(ClusterOptions{Name: "e2m"}))
	e.must(e.j.Config(ConfigOptions{Name: "dev", User: "mue", K8s: "e2m:master"}))
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(script, args...)
		cmd.Env = append(os.Environ(), "CFG_PROVISION_ENV=/dev/null",
			"CFG_PROVISION_CERTS="+e.j.S.CertsDir, "CFG_PROVISION_PLAIN="+e.j.S.PlainDir,
			"CFG_PROVISION_DEVICES="+e.j.S.DevicesDir,
			"PATH="+filepath.Dir(openssl)+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cfg-provision %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	if out := run("seal", "dev"); !strings.Contains(out, "sealed already") {
		t.Errorf("bash seals Go's file again: %s", out)
	}
	before, _ := os.ReadFile(e.j.Store.PlainPath("dev"))
	os.Remove(e.j.Store.PlainPath("dev"))
	run("open", "dev")
	after, _ := os.ReadFile(e.j.Store.PlainPath("dev"))
	if string(before) != string(after) {
		t.Error("bash opens Go's file to something else")
	}
	e.device("dev2")
	run("k8s", "dev2", "e2m", "master")
	cfg := e.plain("dev2")
	if _, ok := cfg["k8s"].(map[string]any)["bootstrap"]; ok {
		t.Error("bash does not see Go's master")
	}
}
