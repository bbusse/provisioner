package settings

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Settings struct {
	CA           string
	Env          Env
	CAName       string
	CertDays     int
	KeyType      string
	WGInstance   string
	WGKeepalive  int
	K8sParentCA  string
	K8sParentDir string
	K8sCADays    int
	CertsDir     string
	PlainDir     string
	DevicesDir   string
	Listen       string
	TLSCert      string
	TLSKey       string
	ClientCA     string
	Admins       []string
}

func readEnvFile(path string, env Env) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		env[strings.TrimSpace(key)] = os.Expand(value, func(name string) string {
			if v, ok := env[name]; ok {
				return v
			}
			return os.Getenv(name)
		})
	}
	return scanner.Err()
}

type Env map[string]string

func ReadEnv(defaultFile string) (Env, error) {
	env := Env{}
	envFile, ok := os.LookupEnv("PROVISIONER_ENV")
	if !ok {
		envFile, ok = os.LookupEnv("CFG_PROVISION_ENV")
	}
	if !ok {
		envFile = defaultFile
	}
	if envFile != "" {
		if err := readEnvFile(envFile, env); err != nil {
			return nil, err
		}
	}
	return env, nil
}

func ReadFile(path string) (Env, error) {
	env := Env{}
	if err := readEnvFile(path, env); err != nil {
		return nil, err
	}
	return env, nil
}

func (env Env) Lookup(key string) (string, bool) {
	if v, ok := os.LookupEnv(key); ok {
		return v, true
	}
	v, ok := env[key]
	return v, ok
}

func (env Env) Get(key, def string) string {
	if v, ok := env.Lookup(key); ok && v != "" {
		return v
	}
	return def
}

func (env Env) Number(key string, def int) int {
	if n, err := strconv.Atoi(env.Get(key, "")); err == nil {
		return n
	}
	return def
}

func (env Env) List(key string) []string {
	var out []string
	for _, item := range strings.Split(env.Get(key, ""), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func Load() (*Settings, error) {
	env, err := ReadEnv("")
	if err != nil {
		return nil, err
	}
	data := env.Get("PROVISIONER_DATA", ".")
	return &Settings{
		CA:           env.Get("PROVISIONER_CA", ""),
		Env:          env,
		CAName:       env.Get("CA_NAME", "e2m-hqb"),
		CertDays:     env.Number("CERT_DAYS", 397),
		KeyType:      env.Get("KEY_TYPE", "ec"),
		WGInstance:   env.Get("WG_INSTANCE", "e2m"),
		WGKeepalive:  env.Number("WG_KEEPALIVE", 25),
		K8sParentCA:  env.Get("K8S_PARENT_CA", "e2m-0"),
		K8sParentDir: env.Get("K8S_PARENT_DIR", ""),
		K8sCADays:    env.Number("K8S_CA_DAYS", 3650),
		CertsDir:     env.Get("CFG_PROVISION_CERTS", filepath.Join(data, "certs")),
		PlainDir:     env.Get("CFG_PROVISION_PLAIN", filepath.Join(data, "plain")),
		DevicesDir:   env.Get("CFG_PROVISION_DEVICES", filepath.Join(data, "devices")),
		Listen:       env.Get("PROVISIONER_LISTEN", ":8444"),
		TLSCert:      env.Get("PROVISIONER_TLS_CERT", ""),
		TLSKey:       env.Get("PROVISIONER_TLS_KEY", ""),
		ClientCA:     env.Get("PROVISIONER_CLIENT_CA", ""),
		Admins:       env.List("PROVISIONER_ADMINS"),
	}, nil
}
