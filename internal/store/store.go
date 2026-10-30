package store

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/bbusse/provisioner/internal/cms"
	"github.com/bbusse/provisioner/internal/pki"
)

const SignerName = cms.SignerCN

var reName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

func CheckName(name string) error {
	if !reName.MatchString(name) {
		return fmt.Errorf("not a host or device name: %s", name)
	}
	return nil
}

type Store struct {
	Certs   string
	Plain   string
	Devices string
}

func (s *Store) CertDir(name string) string   { return filepath.Join(s.Certs, name) }
func (s *Store) CertPath(name string) string  { return filepath.Join(s.Certs, name, name+".pem") }
func (s *Store) KeyPath(name string) string   { return filepath.Join(s.Certs, name, name+".key") }
func (s *Store) PlainPath(name string) string { return filepath.Join(s.Plain, name+".toml") }
func (s *Store) SealedPath(name string) string {
	return filepath.Join(s.Devices, name+".cms")
}

func Exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

// Device is what the data holds for one device
type Device struct {
	Name   string `json:"name"`
	Plain  bool   `json:"plain"`
	Sealed bool   `json:"sealed"`
	Cert   bool   `json:"cert"`
}

// List is every device with a plain or sealed file, by name
func (s *Store) List() []Device {
	names := map[string]bool{}
	for _, pattern := range []string{filepath.Join(s.Plain, "*.toml"), filepath.Join(s.Devices, "*.cms")} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			name := strings.TrimSuffix(filepath.Base(m), filepath.Ext(m))
			if CheckName(name) == nil {
				names[name] = true
			}
		}
	}
	var out []Device
	for name := range names {
		_, plainErr := os.Stat(s.PlainPath(name))
		_, sealedErr := os.Stat(s.SealedPath(name))
		out = append(out, Device{Name: name, Plain: plainErr == nil, Sealed: sealedErr == nil, Cert: s.HasCert(name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) HasCert(name string) bool {
	return Exists(s.CertPath(name)) && Exists(s.KeyPath(name))
}

func WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

func PrivateDir(paths ...string) error {
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return err
		}
	}
	return nil
}

type Signer struct {
	Cert  *x509.Certificate
	Key   crypto.Signer
	Roots *x509.CertPool
}

func (s *Store) Signer() (*Signer, error) {
	dir := s.CertDir(SignerName)
	if !Exists(filepath.Join(dir, SignerName+".pem")) || !Exists(filepath.Join(dir, SignerName+".key")) {
		return nil, fmt.Errorf("no signer in %s, run signer", dir)
	}
	cert, err := pki.ReadCert(filepath.Join(dir, SignerName+".pem"))
	if err != nil {
		return nil, err
	}
	key, err := pki.ReadKey(filepath.Join(dir, SignerName+".key"))
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	cas, err := pki.ParseCerts(data)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	for _, c := range cas {
		roots.AddCert(c)
	}
	return &Signer{cert, key, roots}, nil
}

func (s *Store) CheckTOML(path string) error {
	name := filepath.Base(path)
	name = name[:len(name)-len(filepath.Ext(name))]
	if err := CheckName(name); err != nil {
		return err
	}
	var cfg map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return fmt.Errorf("not a valid device file: %s: %v", path, err)
	}
	if system, ok := cfg["system"].(map[string]any); ok {
		if host, ok := system["hostname"]; ok && host != name {
			return fmt.Errorf("not a valid device file: %s: hostname %v is not the file name and CN %s", path, host, name)
		}
	}
	return nil
}

func (s *Store) Unseal(path string, signer *Signer) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content, _, err := cms.Open(data, signer.Cert, signer.Key, signer.Roots, time.Now())
	return content, err
}

func (s *Store) Seal(name string, signer *Signer, log func(string, ...any)) error {
	plainPath := s.PlainPath(name)
	plain, err := os.ReadFile(plainPath)
	if err != nil {
		return fmt.Errorf("no %s", plainPath)
	}
	if !Exists(s.CertPath(name)) {
		return fmt.Errorf("no client certificate %s, run device %s", s.CertPath(name), name)
	}
	if err := s.CheckTOML(plainPath); err != nil {
		return err
	}
	cert, err := pki.ReadCert(s.CertPath(name))
	if err != nil {
		return err
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: signer.Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("%s is not from the signer's CA", s.CertPath(name))
	}

	sealedPath := s.SealedPath(name)
	if Exists(sealedPath) {
		if current, err := s.Unseal(sealedPath, signer); err == nil && bytes.Equal(current, plain) {
			if key, err := pki.ReadKey(s.KeyPath(name)); err == nil {
				data, _ := os.ReadFile(sealedPath)
				if der, err := cms.DecodePEM(data); err == nil {
					if _, err := cms.Decrypt(der, cert, key); err == nil {
						log("devices/%s.cms is sealed already", name)
						return nil
					}
				}
			}
		}
	}

	sealed, err := cms.Seal(plain, signer.Cert, signer.Key, cert, signer.Cert)
	if err != nil {
		return fmt.Errorf("could not seal %s: %w", plainPath, err)
	}
	check, _, err := cms.Open(sealed, signer.Cert, signer.Key, signer.Roots, time.Now())
	if err != nil || !bytes.Equal(check, plain) {
		return fmt.Errorf("devices/%s.cms does not open to %s", name, plainPath)
	}
	if err := os.MkdirAll(s.Devices, 0o755); err != nil {
		return err
	}
	if err := WriteFile(sealedPath, sealed, 0o644); err != nil {
		return err
	}
	log("sealed devices/%s.cms for %s", name, name)
	return nil
}

func (s *Store) Open(name string, signer *Signer, log func(string, ...any)) error {
	sealedPath := s.SealedPath(name)
	if _, err := os.Stat(sealedPath); err != nil {
		return fmt.Errorf("no %s", sealedPath)
	}
	content, err := s.Unseal(sealedPath, signer)
	if err != nil {
		return fmt.Errorf("%s does not decrypt with the signer's key or was not signed by %s", sealedPath, SignerName)
	}
	if err := PrivateDir(s.Plain); err != nil {
		return err
	}
	plainPath := s.PlainPath(name)
	if current, err := os.ReadFile(plainPath); err == nil && !bytes.Equal(current, content) {
		return fmt.Errorf("%s differs from %s, move it away first", plainPath, sealedPath)
	}
	if err := WriteFile(plainPath, content, 0o600); err != nil {
		return err
	}
	log("opened devices/%s.cms to %s", name, plainPath)
	return nil
}
