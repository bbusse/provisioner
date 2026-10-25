package fetch

import "testing"

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
