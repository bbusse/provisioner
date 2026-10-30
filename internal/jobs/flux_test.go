package jobs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbusse/provisioner/internal/devicefile"
	"golang.org/x/crypto/ssh"
)

func fakeHost(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	scanned := ScanHostKey
	t.Cleanup(func() { ScanHostKey = scanned })
	ScanHostKey = func(addr string) (ssh.PublicKey, error) {
		if addr != "git.example.org:2222" {
			t.Errorf("scanned %s", addr)
		}
		return key, nil
	}
	return key
}

func TestFluxGivesTheMastersADeployKey(t *testing.T) {
	e := setup(t)
	e.signer()
	host := fakeHost(t)
	e.must(e.j.Cluster(ClusterOptions{Name: "example"}))
	e.device("m1")
	e.device("c1")
	e.must(e.j.K8s("m1", "example", "master"))
	e.must(e.j.K8s("c1", "example", "client"))

	const repo = "ssh://git@git.example.org:2222/org/fleet.git"
	e.must(e.j.Flux("example", repo))
	dir := filepath.Join(e.j.S.CertsDir, "k8s-example", "flux")
	hosts, _ := os.ReadFile(filepath.Join(dir, "known_hosts"))
	if want := "[git.example.org]:2222 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host))) + "\n"; string(hosts) != want {
		t.Errorf("known_hosts %q, want %q", hosts, want)
	}
	if info, err := os.Stat(filepath.Join(dir, "identity")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("identity %v %v", info, err)
	}
	if !e.logged(`read-only deploy key to ` + repo + `:\n  ssh-ed25519 \S+ flux-example$`) {
		t.Errorf("did not say what to add: %q", e.log)
	}

	m1, err := devicefile.Parse([]byte(e.opens("m1", "m1")))
	e.must(err)
	if len(m1.K8s.Flux) != 2 || m1.K8s.Flux[0].Name != "identity" || !strings.Contains(m1.K8s.Flux[0].PEM, "OPENSSH PRIVATE KEY") {
		t.Errorf("m1 flux %+v", m1.K8s.Flux)
	}
	if c1, err := os.ReadFile(e.j.Store.PlainPath("c1")); err != nil || strings.Contains(string(c1), "[k8s.flux]") {
		t.Error("a client got the deploy key")
	}
	var m bytes.Buffer
	e.must(e.j.Export("m1", &m))
	files := untar(t, m.Bytes())
	for name, mode := range map[string]int64{"k8s-flux/": 0o700, "k8s-flux/identity": 0o600, "k8s-flux/known_hosts": 0o600} {
		if h, ok := files[name]; !ok || h.Mode != mode {
			t.Errorf("%s: %+v", name, h)
		}
	}

	e.device("m2")
	e.must(e.j.K8s("m2", "example", "master"))
	m2, err := devicefile.Parse([]byte(e.opens("m2", "m2")))
	e.must(err)
	if len(m2.K8s.Flux) != 2 || m2.K8s.Flux[0].PEM != m1.K8s.Flux[0].PEM {
		t.Error("a later master did not get the same deploy key")
	}

	newHost := fakeHost(t)
	e.must(e.j.Flux("example", repo))
	again, err := devicefile.Parse([]byte(e.opens("m1", "m1")))
	e.must(err)
	if again.K8s.Flux[0].PEM != m1.K8s.Flux[0].PEM {
		t.Error("a second run made a new deploy key")
	}
	if want := "[git.example.org]:2222 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newHost))); again.K8s.Flux[1].PEM != want {
		t.Errorf("known_hosts %q, want %q", again.K8s.Flux[1].PEM, want)
	}
	for _, device := range []string{"m1", "m2"} {
		text, _ := os.ReadFile(e.j.Store.PlainPath(device))
		if n := strings.Count(string(text), "[k8s.flux]"); n != 1 {
			t.Errorf("%s has %d [k8s.flux] sections", device, n)
		}
	}
	for _, bad := range []string{"https://git.example.org/org/fleet", "ssh://git.example.org/org/fleet", "git@git.example.org:org/fleet"} {
		if err := e.j.Flux("example", bad); err == nil {
			t.Errorf("took %s", bad)
		}
	}
	if err := e.j.Flux("nocluster", repo); err == nil {
		t.Error("made a key for a cluster that does not exist")
	}
}

func TestDropFluxKeepsWhatFollows(t *testing.T) {
	text := "[k8s]\ncluster = \"x\"\n\n[k8s.flux]\nidentity = \"\"\"\nKEY\n\"\"\"\nknown_hosts = \"\"\"\n[git.example.org]:2222 ssh-ed25519 AAAA\n\"\"\"\n\n[wg]\nprivate_key = \"k\"\n"
	if got, want := dropFlux(text), "[k8s]\ncluster = \"x\"\n\n[wg]\nprivate_key = \"k\"\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
