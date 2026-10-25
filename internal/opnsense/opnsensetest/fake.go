package opnsensetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type CA struct {
	UUID string
	Ref  string
	Name string
	Cert *x509.Certificate
	Key  crypto.Signer
}

func (ca *CA) PEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}))
}

type Peer struct {
	UUID, Name, PubKey, PSK, Address, Server string
}

type Fake struct {
	Server   *httptest.Server
	Key      string
	Secret   string
	CAs      []*CA
	Certs    map[string]*x509.Certificate
	Descrs   map[string]string
	Peers    []Peer
	Requests []string
	mu       sync.Mutex
	next     int
}

func NewCA(name string, notAfter time.Time) *CA {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	cert, _ := x509.ParseCertificate(der)
	return &CA{Name: name, Cert: cert, Key: key}
}

func Start() *Fake {
	f := &Fake{
		Key:    "testkey",
		Secret: "testsecret",
		Certs:  map[string]*x509.Certificate{},
		Descrs: map[string]string{},
	}
	for i, name := range []string{"e2m-hqb", "e2m-0"} {
		ca := NewCA(name, time.Now().AddDate(2, 0, 0))
		ca.UUID = fmt.Sprintf("ca-uuid-%d", i)
		ca.Ref = fmt.Sprintf("caref%d", i)
		f.CAs = append(f.CAs, ca)
	}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	return f
}

func (f *Fake) Close() { f.Server.Close() }

func (f *Fake) CA(name string) *CA {
	for _, ca := range f.CAs {
		if ca.Name == name {
			return ca
		}
	}
	return nil
}

func (f *Fake) Pin() string {
	sum := sha256.Sum256(f.Server.Certificate().RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
}

func (f *Fake) Addr() string {
	return f.Server.Listener.Addr().String()
}

func (f *Fake) WriteKeyFile(dir string) string {
	path := filepath.Join(dir, "apikey.txt")
	os.WriteFile(path, []byte("key="+f.Key+"\nsecret="+f.Secret+"\n"), 0o600)
	return path
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	user, pass, ok := r.BasicAuth()
	if !ok || user != f.Key || pass != f.Secret {
		http.Error(w, `{"status":401}`, http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	f.Requests = append(f.Requests, r.Method+" "+path)
	parts := strings.Split(path, "/")
	switch {
	case r.Method == "GET" && path == "trust/ca/search":
		var rows []map[string]string
		for _, ca := range f.CAs {
			rows = append(rows, map[string]string{"uuid": ca.UUID, "descr": ca.Name, "refid": ca.Ref})
		}
		reply(w, map[string]any{"rows": rows})
	case r.Method == "GET" && path == "trust/cert/ca_list":
		var rows []map[string]string
		for _, ca := range f.CAs {
			rows = append(rows, map[string]string{"caref": ca.Ref, "descr": ca.Name})
		}
		reply(w, map[string]any{"rows": rows})
	case r.Method == "POST" && len(parts) == 5 && parts[1] == "ca" && parts[2] == "generate_file":
		for _, ca := range f.CAs {
			if ca.UUID == parts[3] && parts[4] == "crt" {
				reply(w, map[string]string{"status": "ok", "payload": ca.PEM()})
				return
			}
		}
		reply(w, map[string]string{"status": "failed"})
	case r.Method == "GET" && path == "trust/cert/search":
		var rows []map[string]string
		for uuid, descr := range f.Descrs {
			rows = append(rows, map[string]string{"uuid": uuid, "descr": descr})
		}
		reply(w, map[string]any{"rows": rows})
	case r.Method == "POST" && path == "trust/cert/add":
		f.sign(w, r)
	case r.Method == "POST" && len(parts) == 5 && parts[1] == "cert" && parts[2] == "generate_file":
		cert, ok := f.Certs[parts[3]]
		if !ok || parts[4] != "crt" {
			reply(w, map[string]string{"status": "failed"})
			return
		}
		reply(w, map[string]string{"status": "ok", "payload": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))})
	case r.Method == "GET" && path == "wireguard/server/search_server":
		reply(w, map[string]any{"rows": []map[string]string{
			{"uuid": "wg-uuid", "name": "e2m", "port": "51820", "tunneladdress": "10.99.0.1/24,fd99::1/64"},
		}})
	case r.Method == "GET" && path == "wireguard/client/search_client":
		var rows []map[string]string
		for _, p := range f.Peers {
			rows = append(rows, map[string]string{"uuid": p.UUID, "name": p.Name})
		}
		reply(w, map[string]any{"rows": rows})
	case r.Method == "GET" && strings.HasPrefix(path, "wireguard/client/get_server_info/"):
		reply(w, map[string]string{
			"status": "ok", "address": fmt.Sprintf("10.99.0.%d/32", 4+len(f.Peers)),
			"pubkey": "serverpub=", "endpoint": "vpn.example.org", "allowed_ips": "",
		})
	case r.Method == "POST" && path == "wireguard/client/add_client":
		var body struct {
			Client map[string]string `json:"client"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.next++
		p := Peer{UUID: "peer-" + strconv.Itoa(f.next), Name: body.Client["name"], PubKey: body.Client["pubkey"],
			PSK: body.Client["psk"], Address: body.Client["tunneladdress"], Server: body.Client["servers"]}
		f.Peers = append(f.Peers, p)
		reply(w, map[string]string{"result": "saved", "uuid": p.UUID})
	case r.Method == "POST" && path == "wireguard/service/reconfigure":
		reply(w, map[string]string{"result": "ok"})
	default:
		http.NotFound(w, r)
	}
}

func (f *Fake) sign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Cert map[string]string `json:"cert"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := body.Cert
	var ca *CA
	for _, candidate := range f.CAs {
		if candidate.Ref == c["caref"] {
			ca = candidate
		}
	}
	block, _ := pem.Decode([]byte(c["csr_payload"]))
	if ca == nil || block == nil || c["action"] != "sign_csr" {
		reply(w, map[string]any{"result": "failed", "validations": map[string]string{"cert.caref": "bad request"}})
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		reply(w, map[string]any{"result": "failed", "validations": map[string]string{"cert.csr_payload": err.Error()}})
		return
	}
	days, _ := strconv.Atoi(c["lifetime"])
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(0, 0, days),
	}
	switch c["cert_type"] {
	case "usr_cert":
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "server_cert":
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "v3_ca":
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	for _, name := range strings.Split(c["altnames_dns"], "\n") {
		if name != "" && c["cert_type"] == "server_cert" {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	for _, ip := range strings.Split(c["altnames_ip"], "\n") {
		if parsed := net.ParseIP(ip); parsed != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, parsed)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		reply(w, map[string]any{"result": "failed", "validations": map[string]string{"cert": err.Error()}})
		return
	}
	cert, _ := x509.ParseCertificate(der)
	f.next++
	uuid := "cert-" + strconv.Itoa(f.next)
	f.Certs[uuid] = cert
	f.Descrs[uuid] = c["descr"]
	reply(w, map[string]string{"result": "saved", "uuid": uuid})
}
