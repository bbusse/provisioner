package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bbusse/provisioner/internal/jobs"
	"github.com/bbusse/provisioner/internal/mtls"
	"github.com/bbusse/provisioner/internal/settings"
	"github.com/bbusse/provisioner/internal/store"
)

type Response struct {
	Log   []string `json:"log"`
	Error string   `json:"error,omitempty"`
}

type Device struct {
	Name   string `json:"name"`
	Plain  bool   `json:"plain"`
	Sealed bool   `json:"sealed"`
	Cert   bool   `json:"cert"`
}

type Server struct {
	Settings *settings.Settings
	NewJobs  func(*settings.Settings, func(string, ...any)) *jobs.Jobs
	Logger   *log.Logger
	mu       sync.Mutex
}

func (s *Server) TLSConfig() (*tls.Config, error) {
	caPath := s.Settings.ClientCA
	if caPath == "" {
		caPath = filepath.Join(s.Settings.CertsDir, store.SignerName, "ca.pem")
	}
	return mtls.ServerConfig(s.Settings.TLSCert, s.Settings.TLSKey, caPath)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /v1/devices", s.admin(s.devices))
	mux.HandleFunc("POST /v1/signer", s.job(func(j *jobs.Jobs, r *http.Request, _ []byte) error {
		return j.Signer()
	}))
	mux.HandleFunc("POST /v1/servers/{name}", s.job(func(j *jobs.Jobs, r *http.Request, body []byte) error {
		var req struct {
			SANs []string `json:"sans"`
		}
		if err := decode(body, &req); err != nil {
			return err
		}
		return j.Server(r.PathValue("name"), req.SANs)
	}))
	mux.HandleFunc("POST /v1/devices/{name}", s.job(func(j *jobs.Jobs, r *http.Request, _ []byte) error {
		return j.Device(r.PathValue("name"))
	}))
	mux.HandleFunc("POST /v1/devices/{name}/config", s.job(func(j *jobs.Jobs, r *http.Request, body []byte) error {
		var o jobs.ConfigOptions
		if err := decode(body, &o); err != nil {
			return err
		}
		o.Name = r.PathValue("name")
		return j.Config(o)
	}))
	mux.HandleFunc("POST /v1/devices/{name}/k8s", s.job(func(j *jobs.Jobs, r *http.Request, body []byte) error {
		var req struct {
			Cluster string `json:"cluster"`
			Role    string `json:"role"`
		}
		if err := decode(body, &req); err != nil {
			return err
		}
		return j.K8s(r.PathValue("name"), req.Cluster, req.Role)
	}))
	mux.HandleFunc("POST /v1/devices/{name}/open", s.job(func(j *jobs.Jobs, r *http.Request, _ []byte) error {
		return j.Open(r.PathValue("name"))
	}))
	mux.HandleFunc("POST /v1/clusters/{name}", s.job(func(j *jobs.Jobs, r *http.Request, body []byte) error {
		var o jobs.ClusterOptions
		if err := decode(body, &o); err != nil {
			return err
		}
		o.Name = r.PathValue("name")
		return j.Cluster(o)
	}))
	mux.HandleFunc("POST /v1/seal", s.job(func(j *jobs.Jobs, r *http.Request, body []byte) error {
		var req struct {
			Names []string `json:"names"`
		}
		if err := decode(body, &req); err != nil {
			return err
		}
		return j.Seal(req.Names)
	}))
	return mux
}

type badRequest struct{ error }

func decode(body []byte, v any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest{fmt.Errorf("bad request: %w", err)}
	}
	return nil
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	allowed := mtls.Allowed(s.Settings.Admins)
	return func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			cn := mtls.ClientCN(r)
			s.Logger.Printf("refused %q: %s %s", cn, r.Method, r.URL.Path)
			reply(w, http.StatusForbidden, Response{Error: "not an admin"})
			return
		}
		next(w, r)
	}
}

func (s *Server) job(run func(*jobs.Jobs, *http.Request, []byte) error) http.HandlerFunc {
	return s.admin(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			reply(w, http.StatusBadRequest, Response{Error: err.Error()})
			return
		}
		var resp Response
		s.mu.Lock()
		j := s.NewJobs(s.Settings, func(format string, args ...any) {
			resp.Log = append(resp.Log, fmt.Sprintf(format, args...))
		})
		started := time.Now()
		err = run(j, r, body)
		s.mu.Unlock()
		status := http.StatusOK
		if err != nil {
			resp.Error = err.Error()
			status = http.StatusUnprocessableEntity
			var bad badRequest
			if errors.As(err, &bad) {
				status = http.StatusBadRequest
			}
		}
		s.Logger.Printf("%s %s %s: %d in %s", mtls.ClientCN(r), r.Method, r.URL.Path, status, time.Since(started).Round(time.Millisecond))
		reply(w, status, resp)
	})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	st := &store.Store{Certs: s.Settings.CertsDir, Plain: s.Settings.PlainDir, Devices: s.Settings.DevicesDir}
	names := map[string]bool{}
	for _, pattern := range []string{filepath.Join(st.Plain, "*.toml"), filepath.Join(st.Devices, "*.cms")} {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			name := strings.TrimSuffix(filepath.Base(m), filepath.Ext(m))
			if store.CheckName(name) == nil {
				names[name] = true
			}
		}
	}
	var out []Device
	for name := range names {
		_, plainErr := os.Stat(st.PlainPath(name))
		_, sealedErr := os.Stat(st.SealedPath(name))
		out = append(out, Device{Name: name, Plain: plainErr == nil, Sealed: sealedErr == nil, Cert: st.HasCert(name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	reply(w, http.StatusOK, out)
}

type Client struct {
	URL  string
	HTTP *http.Client
}

func NewClient(url, certFile, keyFile, serverCAFile string) (*Client, error) {
	cfg, err := mtls.ClientConfig(certFile, keyFile, serverCAFile)
	if err != nil {
		return nil, err
	}
	return &Client{
		URL:  strings.TrimRight(url, "/"),
		HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Minute},
	}, nil
}

func (c *Client) Do(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.URL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
