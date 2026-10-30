package fetch

import (
	"strings"
	"testing"
)

func TestPickService(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`[{"address":"fd00::5","port":8443},{"address":"192.168.1.1","port":8443}]`, "https://192.168.1.1:8443"},
		{`[{"address":"fe80::1","port":8443},{"address":"fd00::5","port":"8443"}]`, "https://[fd00::5]:8443"},
		{`[{"address":"0.0.0.0","port":8443},{"address":"10.0.0.1","port":0},{"address":"bogus","port":1}]`, ""},
		{`[{"address":"169.254.1.1","port":8443}]`, ""},
		{`not json`, ""},
		{`null`, ""},
	} {
		if got := pickService([]byte(c.in)); got != c.want {
			t.Errorf("%s: %q, want %q", c.in, got, c.want)
		}
	}
}

func TestInSessionOf(t *testing.T) {
	for _, c := range []struct {
		cgroup string
		want   bool
	}{
		{"0::/user.slice/user-1000.slice/session-3.scope\n", true},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service\n", true},
		{"0::/user.slice/user-10000.slice/session-3.scope\n", false},
		{"0::/system.slice/fetch-provision@moonshine.service\n", false},
		{"0::/\n", false},
		{"", false},
	} {
		if got := inSessionOf([]byte(c.cgroup), "1000"); got != c.want {
			t.Errorf("%q: %v, want %v", c.cgroup, got, c.want)
		}
	}
}

func TestDetachArgs(t *testing.T) {
	env := map[string]string{"PATH": "/usr/bin", "PROVISION_ESP": "/efi", "HOME": "/root"}
	got := strings.Join(detachArgs("/usr/local/bin/provisioner", "moonshine", func(k string) string { return env[k] }), " ")
	want := "--unit=provision-fetch --collect --quiet --setenv=PATH=/usr/bin --setenv=PROVISION_ESP=/efi /usr/local/bin/provisioner fetch moonshine"
	if got != want {
		t.Errorf("%s, want %s", got, want)
	}
}
