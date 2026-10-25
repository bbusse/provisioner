package opnsense

import (
	"os"
	"path/filepath"

	"github.com/bbusse/provisioner/internal/ca"
	"github.com/bbusse/provisioner/internal/settings"
)

func init() {
	ca.Register("opnsense", Open)
}

func Open(env settings.Env) (ca.Backend, error) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".config", "cfg-provision")
	if _, ok := env.Lookup("OPNSENSE_PIN"); !ok {
		own, err := settings.ReadFile(filepath.Join(dir, "opnsense.env"))
		if err != nil {
			return nil, err
		}
		for k, v := range env {
			own[k] = v
		}
		env = own
	}
	connectTo := "pathfinder-1.e2m:8888:[::1]:8888"
	if v, ok := env.Lookup("OPNSENSE_CONNECT_TO"); ok {
		connectTo = v
	}
	return New(env.Get("OPNSENSE_URL", "https://pathfinder-1.e2m:8888"), connectTo, env.Get("OPNSENSE_PIN", ""),
		env.Get("OPNSENSE_API_KEY_FILE", filepath.Join(dir, "pathfinder-1.apikey")))
}
