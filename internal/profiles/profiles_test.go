package profiles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type env struct {
	t        *testing.T
	root     string
	repo     string
	config   map[string]string
	enabled  map[string]bool
	running  map[string]bool
	services []string
	chowns   []string
	requests []*http.Request
	stderr   bytes.Buffer

	lighttpdFails bool
	chownFails    bool
	fetchFails    bool
	status        int
	tarball       []byte
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, root: t.TempDir(), config: map[string]string{}, enabled: map[string]bool{}, running: map[string]bool{}, status: http.StatusOK}
	e.repo = filepath.Join(t.TempDir(), "example-cfg-provision-abc1234")
	e.write("router/www-provision/cgi-bin/provision", "#!/bin/sh\necho cgi\n")
	e.write("router/etc/lighttpd/lighttpd.conf", "server.port = 8443\n")
	e.write("router/etc/init.d/provisioner", "#!/bin/sh /etc/rc.common\nPROG=/usr/sbin/provisioner\n")
	e.write("router/etc/umdns/provision.json", `{ "provision": { "service": "_provision._tcp.local", "port": 8443 } }`+"\n")
	e.write("devices/wheel-fm.toml", "[system]\nhostname = \"wheel-fm\"\n")
	e.write("certs/should-not-land.key", "secret\n")
	for _, s := range []string{"lighttpd", "umdns"} {
		e.rootFile("/etc/init.d/"+s, "#!/bin/sh\n")
	}
	return e
}

func (e *env) write(name, content string) {
	p := filepath.Join(e.repo, name)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) rootFile(name, content string) {
	p := e.root + name
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) pack() []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	base := filepath.Dir(e.repo)
	filepath.WalkDir(e.repo, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(base, p)
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		}
		data, _ := os.ReadFile(p)
		tw.WriteHeader(&tar.Header{Name: rel, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))})
		_, err = tw.Write(data)
		return err
	})
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (e *env) run() int {
	e.services = nil
	e.stderr.Reset()
	f := &Fetcher{
		Root:   e.root,
		Stderr: &e.stderr,
		Config: func(key string) string { return e.config[key] },
		Exec: func(name string, args ...string) error {
			if name == "lighttpd" {
				if e.lighttpdFails {
					return errors.New("does not load")
				}
				return nil
			}
			service := filepath.Base(name)
			switch args[0] {
			case "enabled":
				if e.enabled[service] {
					return nil
				}
				return errors.New("disabled")
			case "running":
				if e.running[service] {
					return nil
				}
				return errors.New("not running")
			case "enable", "disable":
				e.enabled[service] = args[0] == "enable"
			case "start", "restart", "stop":
				e.running[service] = args[0] != "stop"
			}
			e.services = append(e.services, service+" "+strings.Join(args, " "))
			return nil
		},
		Chown: func(path, owner string) error {
			if e.chownFails {
				return errors.New("chown failed")
			}
			e.chowns = append(e.chowns, owner+" "+strings.TrimPrefix(path, e.root))
			return nil
		},
		Client: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			e.requests = append(e.requests, r)
			if e.fetchFails {
				return nil, errors.New("no network")
			}
			body := e.tarball
			if body == nil {
				body = e.pack()
			}
			return &http.Response{StatusCode: e.status, Status: http.StatusText(e.status), Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
		})},
	}
	return f.Run()
}

func (e *env) has(name string) bool {
	_, err := os.Stat(e.root + name)
	return err == nil
}

func (e *env) read(name string) string {
	data, err := os.ReadFile(e.root + name)
	if err != nil {
		e.t.Fatalf("%s: %v", name, err)
	}
	return string(data)
}

func (e *env) mode(name string) fs.FileMode {
	fi, err := os.Stat(e.root + name)
	if err != nil {
		e.t.Fatalf("%s: %v", name, err)
	}
	return fi.Mode().Perm()
}

func (e *env) chowned(want string) bool {
	for _, c := range e.chowns {
		if c == want {
			return true
		}
	}
	return false
}

func (e *env) wantServices(want ...string) {
	e.t.Helper()
	if strings.Join(e.services, "\n") != strings.Join(want, "\n") {
		e.t.Errorf("services\n got %q\nwant %q", e.services, want)
	}
}

const repo = "https://github.com/example/cfg-provision"

func TestNothingHappensWithoutARepository(t *testing.T) {
	e := newEnv(t)
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if len(e.requests) != 0 {
		t.Error("fetched without a repository")
	}
}

func TestAGithubRepositoryIsFetchedAsATarball(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = "https://github.com/example/cfg-provision.git"
	e.config["token"] = "tok123"
	e.run()
	r := e.requests[0]
	if r.URL.String() != "https://api.github.com/repos/example/cfg-provision/tarball/main" {
		t.Errorf("fetched %s", r.URL)
	}
	if r.Header.Get("Authorization") != "Bearer tok123" {
		t.Errorf("authorization %q", r.Header.Get("Authorization"))
	}

	e.config["repo"] = "https://github.com/example/cfg-provision/"
	e.config["ref"] = "v2"
	e.config["token"] = ""
	e.run()
	r = e.requests[1]
	if r.URL.String() != "https://api.github.com/repos/example/cfg-provision/tarball/v2" {
		t.Errorf("fetched %s", r.URL)
	}
	if r.Header.Get("Authorization") != "" {
		t.Error("no token, no header")
	}
}

func TestAnArchiveURLIsUsedAsGiven(t *testing.T) {
	e := newEnv(t)
	e.config["archive"] = "https://git.example.org/cfg-provision/archive/main.tar.gz"
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if e.requests[0].URL.String() != e.config["archive"] {
		t.Errorf("fetched %s", e.requests[0].URL)
	}
}

func TestARepositoryItCannotMapNeedsAnArchiveURL(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = "https://git.example.org/cfg-provision"
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if !strings.Contains(e.stderr.String(), "set provision.main.archive, keeping the current files") {
		t.Errorf("stderr %q", e.stderr.String())
	}
	if len(e.requests) != 0 {
		t.Error("fetched")
	}
}

func TestALocalCopyIsUsedWithoutFetching(t *testing.T) {
	e := newEnv(t)
	e.config["path"] = e.repo
	e.config["repo"] = repo
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if len(e.requests) != 0 {
		t.Error("path wins over repo")
	}
	if !e.has("/etc/provision/wheel-fm.toml") || !e.has("/etc/init.d/provisioner") {
		t.Error("not installed")
	}
}

func TestProvisionerIsTheDefaultServer(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d: %s", rc, e.stderr.String())
	}
	if !strings.Contains(e.read("/etc/init.d/provisioner"), "PROG=/usr/sbin/provisioner") {
		t.Error("init script")
	}
	if m := e.mode("/etc/init.d/provisioner"); m != 0o755 {
		t.Errorf("init script mode %o", m)
	}
	if !e.chowned("root:root /etc/init.d/provisioner.new") {
		t.Errorf("chowns %q", e.chowns)
	}
	if e.has("/etc/lighttpd/lighttpd.conf") || e.has("/www-provision") {
		t.Error("lighttpd's files are left alone")
	}
	if !e.has("/etc/umdns/provision.json") {
		t.Error("umdns")
	}
	if m := e.mode("/etc/provision/wheel-fm.toml"); m != 0o640 {
		t.Errorf("device mode %o", m)
	}
	if !e.chowned("root:www-data /etc/provision/wheel-fm.toml.new") {
		t.Errorf("chowns %q", e.chowns)
	}
	filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if strings.HasSuffix(p, "should-not-land.key") {
			t.Error("certs/ is never installed")
		}
		return nil
	})
	e.wantServices("provisioner enable", "provisioner restart", "umdns restart")
}

func TestProvisionerTakesOverFromLighttpd(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.enabled["lighttpd"] = true
	e.run()
	e.wantServices("lighttpd disable", "lighttpd stop", "provisioner enable", "provisioner restart", "umdns restart")
}

func TestLighttpdServesWhenConfigured(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.config["server"] = "lighttpd"
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d: %s", rc, e.stderr.String())
	}
	if !strings.Contains(e.read("/www-provision/cgi-bin/provision"), "echo cgi") {
		t.Error("cgi")
	}
	if m := e.mode("/www-provision/cgi-bin/provision"); m != 0o755 {
		t.Errorf("cgi mode %o", m)
	}
	if e.read("/etc/lighttpd/lighttpd.conf") != "server.port = 8443\n" {
		t.Error("lighttpd.conf")
	}
	if e.has("/etc/init.d/provisioner") {
		t.Error("no provisioner service in lighttpd mode")
	}
	e.wantServices("lighttpd enable", "lighttpd restart", "umdns restart")
}

func TestLighttpdTakesOverFromProvisioner(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.run()
	e.enabled["provisioner"] = true
	e.config["server"] = "lighttpd"
	e.run()
	e.wantServices("provisioner disable", "provisioner stop", "lighttpd enable", "lighttpd restart")
}

func TestAnUnknownServerChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.config["server"] = "nginx"
	if rc := e.run(); rc != 1 {
		t.Errorf("rc %d", rc)
	}
	if len(e.requests) != 0 || e.has("/etc/provision") {
		t.Error("changed something")
	}
}

func TestASecondRunWithoutChangesRestartsNothing(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.run()
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if e.stderr.Len() != 0 {
		t.Errorf("a run that changes nothing is quiet: %q", e.stderr.String())
	}
	e.wantServices()
}

func TestAChangedInitScriptRestartsProvisioner(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.run()
	e.write("router/etc/init.d/provisioner", "#!/bin/sh /etc/rc.common\nPROG=/usr/sbin/provisioner\nSTART=60\n")
	e.run()
	if !strings.Contains(e.read("/etc/init.d/provisioner"), "START=60") {
		t.Error("not updated")
	}
	e.wantServices("provisioner enable", "provisioner restart")
}

func TestAKeptProvisionerThatIsNotRunningIsStarted(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.rootFile("/etc/init.d/provisioner", "#!/bin/sh /etc/rc.common\nPROG=/usr/sbin/provisioner\n")
	e.rootFile("/etc/umdns/provision.json", `{ "provision": { "service": "_provision._tcp.local", "port": 8443 } }`+"\n")
	e.enabled["provisioner"] = true
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d: %s", rc, e.stderr.String())
	}
	e.wantServices("provisioner enable", "provisioner start")
}

func TestAStoppedServerIsStartedAgain(t *testing.T) {
	for _, server := range []string{"provisioner", "lighttpd"} {
		e := newEnv(t)
		e.config["repo"] = repo
		e.config["server"] = server
		e.run()
		e.running[server] = false
		e.run()
		e.wantServices(server+" enable", server+" start")
		e.run()
		e.wantServices()
	}
}

func TestLighttpdIsNotStartedWithoutTheRepositorysConfig(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.config["server"] = "lighttpd"
	e.rootFile("/etc/lighttpd/lighttpd.conf", "server.port = 80\n")
	e.lighttpdFails = true
	e.run()
	e.wantServices("umdns restart")
}

func TestAChangedDeviceFileRestartsNothing(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.run()
	e.write("devices/wheel-fm.toml", "[system]\nhostname = \"wheel-fm\"\nroles = [\"wg\"]\n")
	e.run()
	if !strings.Contains(e.read("/etc/provision/wheel-fm.toml"), "roles") {
		t.Error("not updated")
	}
	e.wantServices()
}

func TestDevicesGoneFromTheRepositoryAreRemoved(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.run()
	e.rootFile("/etc/provision/ca.pem", "keep\n")
	os.Remove(filepath.Join(e.repo, "devices/wheel-fm.toml"))
	e.write("devices/new-dev.toml", "[system]\n")
	e.run()
	if e.has("/etc/provision/wheel-fm.toml") {
		t.Error("not removed")
	}
	if !e.has("/etc/provision/new-dev.toml") || !e.has("/etc/provision/ca.pem") {
		t.Error("only device files are pruned")
	}
}

func TestSealedDeviceFilesAreInstalledAndPruned(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.write("devices/sealed-dev.cms", "-----BEGIN CMS-----\nsealed\n-----END CMS-----\n")
	e.run()
	if !strings.Contains(e.read("/etc/provision/sealed-dev.cms"), "sealed") {
		t.Error("not installed")
	}
	if m := e.mode("/etc/provision/sealed-dev.cms"); m != 0o640 {
		t.Errorf("mode %o", m)
	}
	if !e.chowned("root:www-data /etc/provision/sealed-dev.cms.new") {
		t.Errorf("chowns %q", e.chowns)
	}
	os.Remove(filepath.Join(e.repo, "devices/sealed-dev.cms"))
	e.run()
	if e.has("/etc/provision/sealed-dev.cms") || !e.has("/etc/provision/wheel-fm.toml") {
		t.Error("prune")
	}
}

func TestAFileThatIsNotADeviceNameIsSkipped(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.write("devices/.hidden.toml", "x\n")
	e.write("devices/bad name.toml", "x\n")
	e.run()
	if e.has("/etc/provision/.hidden.toml") || e.has("/etc/provision/bad name.toml") {
		t.Error("installed")
	}
	if !e.has("/etc/provision/wheel-fm.toml") {
		t.Error("good one missing")
	}
}

func TestAnArchiveWithoutRouterChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.run()
	os.RemoveAll(filepath.Join(e.repo, "router"))
	os.Remove(filepath.Join(e.repo, "devices/wheel-fm.toml"))
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if !e.has("/etc/provision/wheel-fm.toml") {
		t.Error("devices are not pruned from a broken archive")
	}
	e.wantServices()
}

func TestAFailedFetchKeepsTheCurrentFiles(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.run()
	e.fetchFails = true
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if !strings.Contains(e.stderr.String(), "could not fetch") || !strings.Contains(e.stderr.String(), "keeping the current files") {
		t.Errorf("stderr %q", e.stderr.String())
	}
	e.fetchFails = false
	e.status = http.StatusNotFound
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if !e.has("/etc/provision/wheel-fm.toml") || !e.has("/etc/init.d/provisioner") {
		t.Error("files gone")
	}
	e.wantServices()
}

func TestABrokenArchiveKeepsTheCurrentFiles(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.tarball = []byte("not a tarball")
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if !strings.Contains(e.stderr.String(), "is not a gzipped tar archive") {
		t.Errorf("stderr %q", e.stderr.String())
	}
}

func TestAnArchiveThatLeavesItsDirectoryIsRefused(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	zw.Close()
	e.tarball = buf.Bytes()
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
	if !strings.Contains(e.stderr.String(), "leaves the archive") {
		t.Errorf("stderr %q", e.stderr.String())
	}
}

func TestAFileItCannotInstallIsAnError(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.chownFails = true
	if rc := e.run(); rc != 1 {
		t.Errorf("rc %d", rc)
	}
	filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if strings.HasSuffix(p, ".new") {
			t.Errorf("half-installed %s", p)
		}
		return nil
	})
}

func TestALighttpdConfigThatDoesNotLoadIsNotInstalled(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.config["server"] = "lighttpd"
	e.run()
	e.write("router/etc/lighttpd/lighttpd.conf", "server.port = 9443\n")
	e.write("devices/wheel-fm.toml", "[system]\nroles = [\"wg\"]\n")
	e.lighttpdFails = true
	if rc := e.run(); rc != 1 {
		t.Errorf("rc %d", rc)
	}
	if e.read("/etc/lighttpd/lighttpd.conf") != "server.port = 8443\n" {
		t.Error("the working config stays")
	}
	if !strings.Contains(e.read("/etc/provision/wheel-fm.toml"), "roles") {
		t.Error("device files still update")
	}
	e.wantServices()
}

func TestProvisionerDoesNotNeedALoadingLighttpdConfig(t *testing.T) {
	e := newEnv(t)
	e.config["repo"] = repo
	e.lighttpdFails = true
	if rc := e.run(); rc != 0 {
		t.Errorf("rc %d", rc)
	}
}
