package jobs

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bbusse/provisioner/internal/ca"
	"github.com/bbusse/provisioner/internal/pki"
	"github.com/bbusse/provisioner/internal/store"
)

type ClusterOptions struct {
	Name        string `json:"-"`
	Endpoint    string `json:"endpoint,omitempty"`
	Method      string `json:"method,omitempty"`
	PodCIDR     string `json:"pod_cidr,omitempty"`
	ServiceCIDR string `json:"service_cidr,omitempty"`
}

var (
	reEndpoint = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$`)
	reMethod   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	reCIDR     = regexp.MustCompile(`^[0-9A-Fa-f.:]+/[0-9]{1,3}$`)
)

func (o *ClusterOptions) defaults() error {
	if err := store.CheckName(o.Name); err != nil {
		return err
	}
	if o.Endpoint == "" {
		o.Endpoint = o.Name + ".k8s.internal:6443"
	}
	if o.Method == "" {
		o.Method = "mdns"
	}
	if o.PodCIDR == "" {
		o.PodCIDR = "10.244.0.0/16"
	}
	if o.ServiceCIDR == "" {
		o.ServiceCIDR = "10.96.0.0/12"
	}
	if !reEndpoint.MatchString(o.Endpoint) {
		return fmt.Errorf("not HOST:PORT: %s", o.Endpoint)
	}
	if !reMethod.MatchString(o.Method) {
		return fmt.Errorf("not a method: %s", o.Method)
	}
	for _, c := range []string{o.PodCIDR, o.ServiceCIDR} {
		if !reCIDR.MatchString(c) {
			return fmt.Errorf("not a CIDR: %s", c)
		}
	}
	return nil
}

func (j *Jobs) selfCA(base, cn string) error {
	key, err := pki.GenerateKey(j.S.KeyType)
	if err != nil {
		return err
	}
	cert, err := pki.SelfSignedCA(key, cn, j.S.K8sCADays)
	if err != nil {
		return fmt.Errorf("could not make the CA %s: %w", cn, err)
	}
	keyPEM, err := pki.KeyPEM(key)
	if err != nil {
		return err
	}
	if err := store.WriteFile(base+".key", keyPEM, 0o600); err != nil {
		return err
	}
	return store.WriteFile(base+".crt", pki.CertPEM(cert), 0o644)
}

func (j *Jobs) clusterCA(name, dir string) error {
	descr := "k8s-" + name
	key, err := pki.GenerateKey(j.S.KeyType)
	if err != nil {
		return err
	}
	keyPEM, err := pki.KeyPEM(key)
	if err != nil {
		return err
	}
	if err := store.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600); err != nil {
		return err
	}

	var parent *x509.Certificate
	var cert *x509.Certificate
	var lifetime int
	var signedBy string
	if j.S.K8sParentDir != "" {
		pdir := j.S.K8sParentDir
		if !store.Exists(filepath.Join(pdir, "ca.pem")) || !store.Exists(filepath.Join(pdir, "ca.key")) {
			return fmt.Errorf("no ca.pem and ca.key in %s", pdir)
		}
		if parent, err = pki.ReadCert(filepath.Join(pdir, "ca.pem")); err != nil {
			return err
		}
		parentKey, err := pki.ReadKey(filepath.Join(pdir, "ca.key"))
		if err != nil {
			return err
		}
		if lifetime, err = pki.Lifetime(parent, j.S.K8sCADays, time.Now()); err != nil {
			return err
		}
		if cert, err = pki.IntermediateCA(key.Public(), descr, lifetime, parent, parentKey); err != nil {
			return fmt.Errorf("%s could not sign %s: %w", pdir, descr, err)
		}
		signedBy = filepath.Join(pdir, "ca.pem")
	} else {
		backend, err := j.ca()
		if err != nil {
			return err
		}
		if exists, err := backend.HasCert(descr); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("%s has a certificate named %s already", backend, descr)
		}
		parentPEM, err := backend.CA(j.S.K8sParentCA)
		if err != nil {
			return err
		}
		if parent, err = pki.ParseCert([]byte(parentPEM)); err != nil {
			return err
		}
		if lifetime, err = pki.Lifetime(parent, j.S.K8sCADays, time.Now()); err != nil {
			return err
		}
		csr, err := pki.CSR(key, descr)
		if err != nil {
			return err
		}
		signed, err := backend.Sign(j.S.K8sParentCA, ca.SignRequest{
			Name: descr, Profile: ca.ProfileCA, CSR: string(csr), Days: lifetime,
		})
		if err != nil {
			return err
		}
		if cert, err = pki.ParseCert([]byte(signed.PEM)); err != nil {
			return err
		}
		signedBy = fmt.Sprintf("%s (cert %s)", j.S.K8sParentCA, signed.ID)
	}
	if err := store.WriteFile(filepath.Join(dir, "parent.pem"), pki.CertPEM(parent), 0o644); err != nil {
		return err
	}

	roots := x509.NewCertPool()
	roots.AddCert(parent)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("%s does not verify against its parent", descr)
	}
	if !cert.IsCA {
		return fmt.Errorf("%s is not a CA certificate", descr)
	}
	if !pki.SamePublicKey(cert, key) {
		return fmt.Errorf("%s is not for its key", descr)
	}
	if err := store.WriteFile(filepath.Join(dir, "ca.crt"), pki.CertPEM(cert), 0o644); err != nil {
		return err
	}
	j.Log("%s signed by %s for %d days", descr, signedBy, lifetime)
	return nil
}

func (j *Jobs) Cluster(o ClusterOptions) error {
	if err := o.defaults(); err != nil {
		return err
	}
	dir := filepath.Join(j.S.CertsDir, "k8s-"+o.Name)
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("%s exists, cluster %s is made already", dir, o.Name)
	}
	work := dir + ".new"
	os.RemoveAll(work)
	if err := store.PrivateDir(j.S.CertsDir, work, filepath.Join(work, "etcd")); err != nil {
		return err
	}
	if err := j.selfCA(filepath.Join(work, "front-proxy-ca"), "front-proxy-ca"); err != nil {
		return err
	}
	if err := j.selfCA(filepath.Join(work, "etcd", "ca"), "etcd-ca"); err != nil {
		return err
	}
	sa, err := pki.GenerateRSA(2048)
	if err != nil {
		return err
	}
	saKey, err := pki.KeyPEM(sa)
	if err != nil {
		return err
	}
	saPub, err := pki.PublicPEM(sa)
	if err != nil {
		return err
	}
	if err := store.WriteFile(filepath.Join(work, "sa.key"), saKey, 0o600); err != nil {
		return err
	}
	if err := store.WriteFile(filepath.Join(work, "sa.pub"), saPub, 0o644); err != nil {
		return err
	}
	if err := j.clusterCA(o.Name, work); err != nil {
		return err
	}
	token, err := pki.BootstrapToken()
	if err != nil {
		return err
	}
	ca, err := pki.ReadCert(filepath.Join(work, "ca.crt"))
	if err != nil {
		return err
	}
	text := fmt.Sprintf("[k8s]\ncluster = \"%s\"\nendpoint = \"%s\"\nendpoint_method = \"%s\"\ntoken = \"%s\"\nca_cert_hash = \"%s\"\npod_cidr = \"%s\"\nservice_cidr = \"%s\"\n",
		o.Name, o.Endpoint, o.Method, token, pki.CACertHash(ca), o.PodCIDR, o.ServiceCIDR)
	if err := store.WriteFile(filepath.Join(work, "k8s.toml"), []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Rename(work, dir); err != nil {
		return err
	}
	j.Log("cluster %s in %s, endpoint %s by %s", o.Name, dir, o.Endpoint, o.Method)
	return nil
}

var k8sPKI = [][2]string{
	{"ca_crt", "ca.crt"}, {"ca_key", "ca.key"},
	{"front_proxy_ca_crt", "front-proxy-ca.crt"}, {"front_proxy_ca_key", "front-proxy-ca.key"},
	{"etcd_ca_crt", "etcd/ca.crt"}, {"etcd_ca_key", "etcd/ca.key"},
	{"sa_key", "sa.key"}, {"sa_pub", "sa.pub"},
}

func (j *Jobs) hasMaster(device, cluster string, signer *store.Signer) (bool, error) {
	plains, _ := filepath.Glob(filepath.Join(j.Store.Plain, "*.toml"))
	sealed, _ := filepath.Glob(filepath.Join(j.Store.Devices, "*.cms"))
	for _, f := range append(plains, sealed...) {
		other := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		if other == device {
			continue
		}
		var text []byte
		var err error
		if strings.HasSuffix(f, ".cms") {
			if _, err := os.Stat(j.Store.PlainPath(other)); err == nil {
				continue
			}
			if text, err = j.Store.Unseal(f, signer); err != nil {
				return false, fmt.Errorf("cannot open %s to look for masters of %s", f, cluster)
			}
		} else if text, err = os.ReadFile(f); err != nil {
			return false, err
		}
		if isK8sMaster(string(text), cluster) {
			return true, nil
		}
	}
	return false, nil
}

func (j *Jobs) K8s(device, cluster, role string) error {
	if err := checkDevice(device); err != nil {
		return err
	}
	if err := store.CheckName(cluster); err != nil {
		return err
	}
	if role != "master" && role != "client" {
		return fmt.Errorf("role must be master or client, not %s", role)
	}
	signer, err := j.Store.Signer()
	if err != nil {
		return err
	}
	if err := j.k8sJoin(device, cluster, role, signer); err != nil {
		return err
	}
	j.Log("commit and push devices/%s.cms, routers pull it", device)
	return nil
}

func (j *Jobs) k8sJoin(device, cluster, role string, signer *store.Signer) error {
	dir := filepath.Join(j.S.CertsDir, "k8s-"+cluster)
	section, err := os.ReadFile(filepath.Join(dir, "k8s.toml"))
	if err != nil || len(section) == 0 {
		return fmt.Errorf("no cluster %s in %s, run cluster %s", cluster, dir, cluster)
	}
	plainPath := j.Store.PlainPath(device)
	text, err := os.ReadFile(plainPath)
	if err != nil {
		return fmt.Errorf("no %s, run device %s", plainPath, device)
	}
	if !store.Exists(j.Store.CertPath(device)) {
		return fmt.Errorf("no client certificate for %s, run device %s", device, device)
	}
	if hasSection(string(text), reK8sSection) {
		return fmt.Errorf("%s has a [k8s] section already", plainPath)
	}

	bootstrap := false
	if role == "master" {
		has, err := j.hasMaster(device, cluster, signer)
		if err != nil {
			return err
		}
		bootstrap = !has
	}

	var b strings.Builder
	b.Write(text)
	b.WriteString("\n")
	b.Write(section)
	if bootstrap {
		b.WriteString("bootstrap = true\n")
	}
	if role == "master" {
		b.WriteString("\n[k8s.pki]\n")
		for _, f := range k8sPKI {
			pem, err := os.ReadFile(filepath.Join(dir, f[1]))
			if err != nil {
				return err
			}
			fmt.Fprintf(&b, "%s = \"\"\"\n%s\n\"\"\"\n", f[0], strings.TrimRight(string(pem), "\n"))
		}
		flux, err := fluxSection(j.S.CertsDir, cluster)
		if err != nil {
			return err
		}
		b.WriteString(flux)
	}
	out, err := addRole(b.String(), "k8s-"+role)
	if err != nil {
		return fmt.Errorf("could not add %s to %s: %w", cluster, plainPath, err)
	}
	if err := j.writeChecked(device, out); err != nil {
		return fmt.Errorf("could not add %s to %s: %w", cluster, plainPath, err)
	}
	suffix := ""
	if bootstrap {
		suffix = ", it bootstraps the cluster"
	}
	j.Log("%s is a %s of %s%s", device, role, cluster, suffix)
	return j.Store.Seal(device, signer, j.Log)
}
