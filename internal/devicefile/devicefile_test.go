package devicefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pem(kind string) string {
	return "-----BEGIN " + kind + "-----\nMIIBszCCAVmgAwIBAgIU\nAAAA+/==\n-----END " + kind + "-----\n"
}

func k8sMaster(extra string, skip string) string {
	var pki strings.Builder
	for _, f := range k8sPKIFiles {
		if f.Name == skip {
			continue
		}
		kind := "CERTIFICATE"
		if strings.HasSuffix(f.Name, "_key") {
			kind = "PRIVATE KEY"
		}
		fmt.Fprintf(&pki, "%s = \"\"\"\n%s\"\"\"\n", f.Name, pem(kind))
	}
	return "[system]\nroles = [\"k8s-master\"]\n\n[k8s]\ncluster = \"example\"\ntoken = \"abcdef.0123456789abcdef\"\n" +
		"ca_cert_hash = \"sha256:" + strings.Repeat("ab", 32) + "\"\nbootstrap = true\n" + extra + "\n[k8s.pki]\n" + pki.String()
}

const k8sClient = `[system]
roles = ["k8s-client"]
[k8s]
cluster = "example"
token = "abcdef.0123456789abcdef"
ca_cert_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
`

const unitInstall = `
[Service]
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target`

var corpus = []string{
	`
[system]
hostname = "test-host"
user = "bob"
roles = ["tv", "wg"]
timezone = "Europe/Berlin"

[ssh]
authorized_keys = ["ssh-ed25519 AAAA a@b", "ssh-ed25519 BBBB c@d"]

[wg]
private_key = "priv="
address = ["10.0.0.5/32"]
listen_port = 51820

[[wg.peer]]
public_key = "pub="
endpoint = "vpn.example.org:51820"
allowed_ips = ["10.0.0.0/24", "10.1.0.0/24"]
persistent_keepalive = 25

[[wg.peer]]
public_key = "pub2="
preshared_key = "psk="
`,
	"[system]\nhostname = \"test-host\"",
	"[system]\nhostname = 42\nroles = []",
	"",
	`
[users.zed]
shell = "zsh"
authorized_keys = ["ssh-ed25519 AAAA a@b"]
git-clone = ["https://github.com/example/dotfiles",
             { url = "git@github.com:example/notes.git", dest = "~/notes", ref = "main" },
             "ssh://git@host/x/y/"]

[users.zed.env]
ZED = "1"
EDITOR = "vim"
ALPHA = "  spaced  "

[users.alpha]
env = { B = "2", A = "1" }

[users.bob.systemd."syncthing.service"]
content = """
[Service]
ExecStart=/usr/bin/syncthing serve

[Install]
WantedBy=default.target
"""

[users.bob.systemd."syncthing.service.d/10-gui.conf"]
content = """
[Service]
Environment=X=1
"""
`,
	`
[systemd-system."backup.service"]
content = """
[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup
"""

[systemd-system."backup.timer"]
content = """

[Timer]
OnCalendar=daily

[Install]
WantedBy=timers.target


"""

[systemd-system."sshd.service.d/10-port.conf"]
content = """
[Service]
Environment=PORT=2222
"""

[systemd-system."tv-extra.service"]
content = """
[Service]
ExecStart=/bin/true

[Install]
WantedBy=role-tv.target
"""
start = false

[systemd-system."once.service"]
content = """
[Service]
Type=oneshot
ExecStart=/bin/true
"""
start = true

[systemd-system."getty@.service"]
content = """
[Service]
ExecStart=/bin/true
"""

[systemd-user."syncthing.service"]
content = """
[Service]
ExecStart=/usr/bin/syncthing serve

[Install]
WantedBy=default.target
"""

[systemd-user."quiet.service"]
content = """
[Service]
ExecStart=/bin/true

[Install]
WantedBy=default.target
"""
enable = false
`,
	k8sMaster("", ""),
	k8sMaster("endpoint = \"k8s.home:7443\"\nendpoint_method = \"dns\"\npod_cidr = \"172.20.0.0/16\"\nservice_cidr = \"fd00::/108\"", ""),
	k8sClient,
	k8sClient + "endpoint = \"k8s.home:0080\"\npod_cidr = \"10.1.2.3\"\n",
	k8sClient + "service_cidr = \"FD00:0:0::/64\"\n",

	"[system\nhostname = \"x\"",
	"[system]\nhostname = \"\"\"rw\nvfm\"\"\"",
	"[system]\nhostname = \"  \"",
	"[system]\nhostname = 1.5",
	"[system]\nhostname = true",
	"[ssh]\nauthorized_keys = \"ssh-ed25519 AAAA a@b\"",
	"[ssh]\nauthorized_keys = [[\"x\"]]",
	"[wg]\naddress = [\"10.0.0.5/32\"]",
	"system = \"test-host\"\n[ssh]\nauthorized_keys = []",
	"[wg]\nprivate_key = \"priv=\"\npeer = \"pub=\"",
	"[wg]\nprivate_key = \"priv=\"\n[[wg.peer]]\nendpoint = \"x:1\"",
	"[system]\nuser = \"Bob Root\"",
	"[system]\nuser = \"../etc\"",
	"[system]\nroles = \"tv\"",
	"[system]\nroles = [\"../tv\"]",
	"[system]\ntimezone = \"Europe/../Berlin\"",
	"[users.Bob]\nshell = \"zsh\"",
	"[users]\nmue = \"zsh\"",
	"[users.bob]\nshell = \"../bin/sh\"",
	"[users.bob]\nshell = \"/bin/sh;reboot\"",
	"[users.bob.env]\n\"BAD-NAME\" = \"x\"",
	"[users.bob.env]\nA = [\"x\"]",
	"[users.bob]\ngit-clone = \"https://github.com/a/b\"",
	"[users.bob]\ngit-clone = [\"file:///etc\"]",
	"[users.bob]\ngit-clone = [{ dest = \"~/x\" }]",
	"[users.bob]\ngit-clone = [{ url = \"https://h/a/b\", dest = \"relative\" }]",
	"[users.bob]\ngit-clone = [{ url = \"https://h/a/b\", dest = \"~/../x\" }]",
	"[users.bob]\ngit-clone = [{ url = \"https://h/a/b\", ref = \"a\tb\" }]",
	"[users.bob]\ngit-clone = [42]",
	"[systemd-system.\"../evil.service\"]\ncontent = \"\"\"" + unitInstall + "\"\"\"",
	"[systemd-system.\"evil\"]\ncontent = \"\"\"" + unitInstall + "\"\"\"",
	"[systemd-system.\"a.service.d/../../x.conf\"]\ncontent = \"\"\"" + unitInstall + "\"\"\"",
	"[systemd-system.\"a.service.d/x.conf\"]\ncontent = \"\"\"" + unitInstall + "\"\"\"\nenable = true",
	"[systemd-system.\"a.service\"]\ncontent = \"ExecStart=/bin/true\"",
	"[systemd-system.\"a.service\"]\ncontent = \"\"\"\n[Service]\nExecStart=/bin/true\"\"\"\nenable = true",
	"[systemd-system.\"a.service\"]\ncontent = \"\"\"" + unitInstall + "\"\"\"\nenable = \"yes\"",
	"[systemd-system.\"a.service\"]\ncontent = \"\"\"" + unitInstall + "\"\"\"\nstart = 1",
	"[systemd-user.\"a.service\"]\ncontent = \"\"\"" + unitInstall + "\"\"\"\nstart = true",
	"[systemd-system.\"a.service\"]\nenable = true",
	"[systemd-system]\n\"a.service\" = \"\"\"" + unitInstall + "\"\"\"",
	"[users.bob.systemd.\"a.service\"]\ncontent = \"\"\"" + unitInstall + "\"\"\"\nstart = true",
	"[users.bob]\nsystemd = \"a.service\"",
	"[system]\nroles = [\"k8s-client\"]",
	"[system]\nroles = [\"k8s-master\", \"k8s-client\"]\n[k8s]\ncluster = \"example\"",
	k8sClient + "bootstrap = true",
	k8sClient + "[k8s.pki]\nca_key = \"\"\"" + pem("EC PRIVATE KEY") + "\"\"\"",
	strings.Replace(k8sClient, "abcdef.0123456789abcdef", "abcdef0123456789abcdef", 1),
	strings.Replace(k8sClient, "sha256:0000000000000000000000000000000000000000000000000000000000000000", "sha256:abc", 1),
	k8sClient + "pod_cidr = \"10.244.0.1/16\"",
	k8sClient + "pod_cidr = \"not-a-net\"",
	k8sClient + "endpoint = \"example.k8s.internal\"",
	k8sClient + "endpoint = \"example.k8s.internal:+80\"",
	k8sClient + "endpoint = \"example.k8s.internal:65536\"",
	k8sClient + "endpoint_method = \"../bin/sh\"",
	k8sClient + "bootstrap = \"yes\"",
	strings.Replace(k8sClient, "cluster = \"example\"", "cluster = \"EXAMPLE; reboot\"", 1),
	strings.Replace(k8sClient, "token = \"abcdef.0123456789abcdef\"\n", "", 1),
	k8sMaster("", "sa_pub"),
	strings.Replace(k8sMaster("", ""), "MIIBszCCAVmgAwIBAgIU", "rm -rf /", 1),
}

func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(dir, path)
		out[rel] = string(data)
		return nil
	})
	return out
}

func TestParseMatchesFetchProvisionPython(t *testing.T) {
	cases, err := filepath.Glob(filepath.Join("testdata", "fetch-provision", "*"))
	if err != nil || len(cases) == 0 {
		t.Fatal("no recorded fetch-provision results")
	}
	accepted := 0
	for _, dir := range cases {
		doc, err := os.ReadFile(filepath.Join(dir, "provision.toml"))
		if err != nil {
			t.Fatal(err)
		}
		pyErr, err := os.ReadFile(filepath.Join(dir, "error"))
		refused := err == nil
		cfg, err := Parse(doc)
		if refused != (err != nil) {
			t.Errorf("%s: python refused %v (%s), go %v", dir, refused, strings.TrimSpace(string(pyErr)), err)
			continue
		}
		if err != nil {
			var e *Error
			if !errors.As(err, &e) {
				t.Errorf("%s: %T is not an *Error", dir, err)
				continue
			}
			want := strings.TrimSpace(string(pyErr))
			got := "provision: invalid provisioning file: " + err.Error()
			if e.Kind == "TOMLDecodeError" {
				if !strings.HasPrefix(want, "provision: invalid provisioning file: TOMLDecodeError: ") {
					t.Errorf("%s: python said %q", dir, want)
				}
			} else if e.Kind == "ValueError" && strings.Contains(e.Msg, "network") && strings.HasPrefix(want, "provision: invalid provisioning file: ValueError: ") {
			} else if got != want {
				t.Errorf("%s:\n python %q\n go     %q", dir, want, got)
			}
			continue
		}
		accepted++
		goOut := t.TempDir()
		if err := cfg.WriteOut(goOut); err != nil {
			t.Fatal(err)
		}
		pyTree, goTree := tree(t, filepath.Join(dir, "out")), tree(t, goOut)
		for name, content := range pyTree {
			if goTree[name] != content {
				t.Errorf("%s: %s\n python %q\n go     %q", dir, name, content, goTree[name])
			}
		}
		for name := range goTree {
			if _, ok := pyTree[name]; !ok {
				t.Errorf("%s: go writes %s, python did not", dir, name)
			}
		}
	}
	if accepted < 8 {
		t.Errorf("only %d cases accepted", accepted)
	}
}

func TestUsersKeepTheirOrder(t *testing.T) {
	cfg, err := Parse([]byte(corpus[4]))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, u := range cfg.Users {
		names = append(names, u.Name)
	}
	if strings.Join(names, " ") != "zed alpha bob" {
		t.Errorf("users in %v", names)
	}
	if strings.Join(cfg.Users[0].Env, " ") != "ZED=1 EDITOR=vim ALPHA=spaced" {
		t.Errorf("env in %v", cfg.Users[0].Env)
	}
	if strings.Join(cfg.Users[1].Env, " ") != "B=2 A=1" {
		t.Errorf("inline env in %v", cfg.Users[1].Env)
	}
}

func TestK8sFluxIsForMasters(t *testing.T) {
	const hosts = "[git.example.org]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	flux := func(identity, known string) string {
		return "\n[k8s.flux]\nidentity = \"\"\"\n" + identity + "\"\"\"\nknown_hosts = \"\"\"\n" + known + "\n\"\"\"\n"
	}
	good := k8sMaster("", "") + flux(pem("OPENSSH PRIVATE KEY"), hosts)
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.K8s.Flux) != 2 || cfg.K8s.Flux[1].PEM != hosts {
		t.Errorf("flux %+v", cfg.K8s.Flux)
	}
	out := t.TempDir()
	if err := cfg.WriteOut(out); err != nil {
		t.Fatal(err)
	}
	if files := tree(t, out); files["k8s-flux/known_hosts"] != hosts+"\n" || !strings.Contains(files["k8s-flux/identity"], "OPENSSH PRIVATE KEY") {
		t.Errorf("wrote %v", files)
	}
	if cfg, err := Parse([]byte(k8sMaster("", ""))); err != nil || cfg.K8s.Flux != nil {
		t.Errorf("a master without flux: %v %+v", err, cfg)
	}
	for _, bad := range []string{
		k8sClient + flux(pem("OPENSSH PRIVATE KEY"), hosts),
		k8sMaster("", "") + flux("not a key\n", hosts),
		k8sMaster("", "") + flux(pem("OPENSSH PRIVATE KEY"), "git.example.org not-a-key"),
		k8sMaster("", "") + flux(pem("OPENSSH PRIVATE KEY"), ""),
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
