package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bbusse/provisioner/internal/devicefile"
)

// Export writes DEVICE's k8s.conf and, for a master, k8s-pki/ and k8s-flux/
// as a gzipped tar of /etc/provision, as fetch installs them. It is for nodes that do
// not fetch, like a FreeBSD master, and never runs through the API
func (j *Jobs) Export(device string, w io.Writer) error {
	if err := checkDevice(device); err != nil {
		return err
	}
	path := j.Store.PlainPath(device)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no %s, run open %s", path, device)
	}
	c, err := devicefile.Parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if c.K8s == nil {
		return fmt.Errorf("%s is no node of a cluster, run k8s %s CLUSTER ROLE", device, device)
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now()
	add := func(name string, mode int64, body string) error {
		h := &tar.Header{Name: name, Mode: mode, ModTime: now, Typeflag: tar.TypeReg, Size: int64(len(body))}
		if strings.HasSuffix(name, "/") {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := io.WriteString(tw, body)
		return err
	}
	if err := add("k8s.conf", 0o600, strings.Join(c.K8s.Conf, "\n")+"\n"); err != nil {
		return err
	}
	if len(c.K8s.PKI) > 0 {
		if err := add("k8s-pki/", 0o700, ""); err != nil {
			return err
		}
		if err := add("k8s-pki/etcd/", 0o755, ""); err != nil {
			return err
		}
		for _, f := range c.K8s.PKI {
			if err := add("k8s-pki/"+f.Name, 0o600, f.PEM+"\n"); err != nil {
				return err
			}
		}
	}
	if len(c.K8s.Flux) > 0 {
		if err := add("k8s-flux/", 0o700, ""); err != nil {
			return err
		}
		for _, f := range c.K8s.Flux {
			if err := add("k8s-flux/"+f.Name, 0o600, f.PEM+"\n"); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// Deploy installs what Export writes on HOST over ssh, as root there, and
// replaces the k8s-pki/ and k8s-flux/ a master had before
func (j *Jobs) Deploy(device, host string) error {
	var buf bytes.Buffer
	if err := j.Export(device, &buf); err != nil {
		return err
	}
	cmd := exec.Command("ssh", host, "rm -rf /etc/provision/k8s-pki /etc/provision/k8s-flux && mkdir -p /etc/provision && tar -xpzf - -C /etc/provision")
	cmd.Stdin = &buf
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh %s: %w", host, err)
	}
	j.Log("deployed the k8s configuration of %s to %s", device, host)
	return nil
}
