package router

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type options struct {
	listen string
	cert   string
	key    string
	ca     string
	dir    string
}

var validCN = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

var deviceFiles = []struct{ ext, contentType string }{
	{".cms", "application/cms"},
	{".toml", "application/toml"},
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func Run(args []string) {
	var o options
	fs := flag.NewFlagSet("provisioner router", flag.ExitOnError)
	fs.StringVar(&o.listen, "listen", env("PROVISIONER_ROUTER_LISTEN", ":8443"), "address to listen on")
	fs.StringVar(&o.cert, "cert", env("PROVISIONER_ROUTER_CERT", "/etc/lighttpd/server.pem"), "server certificate (PEM)")
	fs.StringVar(&o.key, "key", env("PROVISIONER_ROUTER_KEY", "/etc/lighttpd/server.key"), "server key (PEM)")
	fs.StringVar(&o.ca, "ca", env("PROVISIONER_ROUTER_CA", "/etc/provision/ca.pem"), "CA that issues the client certificates (PEM)")
	fs.StringVar(&o.dir, "dir", env("PROVISIONER_ROUTER_DIR", "/etc/provision"), "directory with <CN>.cms and <CN>.toml")
	fs.Parse(args)
	log.SetFlags(0)

	srv, c, err := newServer(o)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		log.Fatal(err)
	}

	done := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		defer close(done)
		for s := range sig {
			if s == syscall.SIGHUP {
				c.reload()
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			srv.Shutdown(ctx)
			cancel()
			return
		}
	}()

	log.Printf("listening on %s", ln.Addr())
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-done
}

func newServer(o options) (*http.Server, *certs, error) {
	c := &certs{certFile: o.cert, keyFile: o.key, caFile: o.ca}
	if err := c.reload(); err != nil {
		return nil, nil, err
	}
	srv := &http.Server{
		Handler:           handler(o.dir),
		TLSConfig:         &tls.Config{GetConfigForClient: c.config},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return srv, c, nil
}

type certs struct {
	certFile, keyFile, caFile string

	mu    sync.Mutex
	stamp []os.FileInfo
	cfg   *tls.Config
}

func (c *certs) stat() []os.FileInfo {
	s := make([]os.FileInfo, 3)
	for i, name := range []string{c.certFile, c.keyFile, c.caFile} {
		s[i], _ = os.Stat(name)
	}
	return s
}

func sameStamp(a, b []os.FileInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		switch {
		case a[i] == nil && b[i] == nil:
		case a[i] == nil || b[i] == nil:
			return false
		case !os.SameFile(a[i], b[i]) || a[i].Size() != b[i].Size() || !a[i].ModTime().Equal(b[i].ModTime()):
			return false
		}
	}
	return true
}

func (c *certs) reload() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.load(c.stat())
}

func (c *certs) load(stamp []os.FileInfo) error {
	c.stamp = stamp
	cfg, err := loadConfig(c.certFile, c.keyFile, c.caFile)
	if err != nil {
		if c.cfg != nil {
			log.Printf("keeping current certificates: %v", err)
		}
		return err
	}
	if c.cfg != nil {
		log.Printf("reloaded certificates")
	}
	c.cfg = cfg
	return nil
}

func (c *certs) config(*tls.ClientHelloInfo) (*tls.Config, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s := c.stat(); !sameStamp(s, c.stamp) {
		c.load(s)
	}
	return c.cfg, nil
}

func loadConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s: no certificates", caFile)
	}
	return &tls.Config{
		MinVersion:            tls.VersionTLS12,
		Certificates:          []tls.Certificate{cert},
		NextProtos:            []string{"http/1.1"},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifyClient(roots),
	}, nil
}

func verifyClient(roots *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("no client certificate")
		}
		leaf, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return err
		}
		for _, chain := range chains {
			if len(chain) == 2 {
				return nil
			}
		}
		return fmt.Errorf("client certificate %q is not issued by the CA itself", leaf.Subject.CommonName)
	}
}

func handler(dir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /cgi-bin/provision", func(w http.ResponseWriter, r *http.Request) {
		var cn string
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		if !validCN.MatchString(cn) {
			log.Printf("%s: refused CN %q", r.RemoteAddr, cn)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		for _, f := range deviceFiles {
			name := filepath.Join(dir, cn+f.ext)
			ok, err := serveFile(w, name, f.contentType)
			if err != nil {
				log.Printf("%s: %s: %v", r.RemoteAddr, cn, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if ok {
				log.Printf("%s: served %s", r.RemoteAddr, filepath.Base(name))
				return
			}
		}
		log.Printf("%s: no file for %s", r.RemoteAddr, cn)
		w.Header().Set("Content-Type", "application/toml")
	})
	return mux
}

func serveFile(w http.ResponseWriter, name, contentType string) (bool, error) {
	f, err := os.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, nil
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	if _, err := io.CopyN(w, f, fi.Size()); err != nil {
		log.Printf("%s: %v", name, err)
	}
	return true, nil
}
