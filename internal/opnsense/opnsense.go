package opnsense

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/bbusse/provisioner/internal/ca"
)

type Client struct {
	url    string
	key    string
	secret string
	http   *http.Client
}

func New(url, connectTo, pin, keyFile string) (*Client, error) {
	if pin == "" {
		return nil, errors.New("OPNSENSE_PIN is not set")
	}
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read the API key file %s", keyFile)
	}
	c := &Client{url: strings.TrimRight(url, "/")}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "key="); ok {
			c.key = v
		} else if v, ok := strings.CutPrefix(line, "secret="); ok {
			c.secret = v
		}
	}
	if c.key == "" || c.secret == "" {
		return nil, fmt.Errorf("no key= and secret= in %s", keyFile)
	}

	pins := map[string]bool{}
	for _, p := range strings.Split(pin, ";") {
		pins[strings.TrimPrefix(strings.TrimSpace(p), "sha256//")] = true
	}
	from, to, err := parseConnectTo(connectTo)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if from != "" && addr == from {
				addr = to
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("opnsense: no server certificate")
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
				if !pins[base64.StdEncoding.EncodeToString(sum[:])] {
					return errors.New("opnsense: the server's public key does not match OPNSENSE_PIN")
				}
				return nil
			},
		},
	}
	c.http = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return c, nil
}

func splitHostPort(s string) (string, string, string, bool) {
	var host string
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", "", false
		}
		host, s = s[1:end], s[end+1:]
		if !strings.HasPrefix(s, ":") {
			return "", "", "", false
		}
		s = s[1:]
	} else {
		var ok bool
		if host, s, ok = strings.Cut(s, ":"); !ok {
			return "", "", "", false
		}
	}
	port, rest, _ := strings.Cut(s, ":")
	return host, port, rest, port != ""
}

func parseConnectTo(s string) (string, string, error) {
	if s == "" {
		return "", "", nil
	}
	host, port, rest, ok := splitHostPort(s)
	if !ok {
		return "", "", fmt.Errorf("not HOST:PORT:CONNECT-HOST:CONNECT-PORT: %s", s)
	}
	toHost, toPort, extra, ok := splitHostPort(rest)
	if !ok || extra != "" {
		return "", "", fmt.Errorf("not HOST:PORT:CONNECT-HOST:CONNECT-PORT: %s", s)
	}
	return net.JoinHostPort(host, port), net.JoinHostPort(toHost, toPort), nil
}

func (c *Client) call(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.url+"/api/"+path, reader)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.key, c.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("opnsense %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("opnsense %s: %s: %s", path, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("opnsense %s: %w", path, err)
		}
	}
	return nil
}

type Row map[string]any

func (r Row) String(key string) string {
	switch v := r[key].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(v)
	case nil:
		return ""
	}
	return fmt.Sprint(r[key])
}

func (c *Client) rows(path string) ([]Row, error) {
	var out struct {
		Rows []Row `json:"rows"`
	}
	if err := c.call(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Rows, nil
}

func (c *Client) file(path string) (string, error) {
	var out struct {
		Status  string `json:"status"`
		Payload string `json:"payload"`
	}
	if err := c.call(http.MethodPost, path, struct{}{}, &out); err != nil {
		return "", err
	}
	if out.Status != "ok" || out.Payload == "" {
		return "", fmt.Errorf("opnsense %s: nothing to fetch", path)
	}
	return out.Payload, nil
}

func single(rows []Row, key, value string) (Row, bool) {
	var found []Row
	for _, r := range rows {
		if r.String(key) == value {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		return nil, false
	}
	return found[0], true
}

type caRow struct {
	UUID string
	Ref  string
}

func (c *Client) findCA(name string) (*caRow, error) {
	rows, err := c.rows("trust/ca/search")
	if err != nil {
		return nil, err
	}
	row, ok := single(rows, "descr", name)
	if !ok {
		return nil, fmt.Errorf("no single CA named %s on %s: %w", name, c.url, ca.ErrNotFound)
	}
	refs, err := c.rows("trust/cert/ca_list")
	if err != nil {
		return nil, err
	}
	found := &caRow{UUID: row.String("uuid")}
	for _, r := range refs {
		if r.String("descr") == name {
			found.Ref = r.String("caref")
		}
	}
	if found.Ref == "" {
		return nil, fmt.Errorf("no caref for %s", name)
	}
	return found, nil
}

func (c *Client) CA(name string) (string, error) {
	found, err := c.findCA(name)
	if err != nil {
		return "", err
	}
	pem, err := c.file("trust/ca/generate_file/" + found.UUID + "/crt")
	if err != nil {
		return "", fmt.Errorf("could not fetch the certificate of %s", name)
	}
	return pem, nil
}

func (c *Client) HasCert(name string) (bool, error) {
	rows, err := c.rows("trust/cert/search")
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.String("descr") == name {
			return true, nil
		}
	}
	return false, nil
}

var certTypes = map[ca.Profile]string{
	ca.ProfileClient: "usr_cert",
	ca.ProfileServer: "server_cert",
	ca.ProfileCA:     "v3_ca",
}

func (c *Client) Sign(caName string, r ca.SignRequest) (*ca.Signed, error) {
	certType, ok := certTypes[r.Profile]
	if !ok {
		return nil, fmt.Errorf("no certificate type for the profile %q", r.Profile)
	}
	found, err := c.findCA(caName)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"cert": map[string]string{
		"action":               "sign_csr",
		"descr":                r.Name,
		"caref":                found.Ref,
		"csr_payload":          r.CSR,
		"cert_type":            certType,
		"key_type":             "prime256v1",
		"digest":               "sha256",
		"lifetime":             fmt.Sprint(r.Days),
		"altnames_dns":         strings.Join(r.DNS, "\n"),
		"altnames_ip":          strings.Join(r.IPs, "\n"),
		"private_key_location": "local",
		"commonname":           r.Name,
	}}
	var out struct {
		Result      string          `json:"result"`
		UUID        string          `json:"uuid"`
		Validations json.RawMessage `json:"validations"`
	}
	if err := c.call(http.MethodPost, "trust/cert/add", body, &out); err != nil {
		return nil, err
	}
	if out.Result != "saved" || out.UUID == "" {
		return nil, fmt.Errorf("signing failed: %s", string(out.Validations))
	}
	pem, err := c.file("trust/cert/generate_file/" + out.UUID + "/crt")
	if err != nil {
		return nil, fmt.Errorf("could not fetch the signed certificate %s", out.UUID)
	}
	return &ca.Signed{ID: out.UUID, PEM: pem}, nil
}

func splitList(csv string) []string {
	var out []string
	for _, item := range strings.Split(csv, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func networks(csv string) ([]string, error) {
	var out []string
	for _, a := range splitList(csv) {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			addr, aerr := netip.ParseAddr(a)
			if aerr != nil {
				return nil, fmt.Errorf("not an address: %s", a)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		out = append(out, p.Masked().String())
	}
	return out, nil
}

type serverInfo struct {
	Status     string `json:"status"`
	Address    string `json:"address"`
	PubKey     string `json:"pubkey"`
	Endpoint   string `json:"endpoint"`
	AllowedIPs string `json:"allowed_ips"`
}

func (c *Client) AddPeer(instance, name string, r ca.PeerRequest) (*ca.Peer, error) {
	rows, err := c.rows("wireguard/server/search_server")
	if err != nil {
		return nil, err
	}
	server, ok := single(rows, "name", instance)
	if !ok {
		return nil, fmt.Errorf("no single WireGuard instance named %s on %s: %w", instance, c.url, ca.ErrNotFound)
	}
	uuid := server.String("uuid")
	peers, err := c.rows("wireguard/client/search_client")
	if err != nil {
		return nil, err
	}
	for _, p := range peers {
		if p.String("name") == name {
			return nil, fmt.Errorf("%s already has a peer named %s: %w", instance, name, ca.ErrExists)
		}
	}
	var info serverInfo
	if err := c.call(http.MethodGet, "wireguard/client/get_server_info/"+uuid, nil, &info); err != nil {
		return nil, err
	}
	if info.Status != "ok" {
		return nil, fmt.Errorf("no server info for %s", instance)
	}
	if info.Address == "" || info.PubKey == "" || info.Endpoint == "" {
		return nil, fmt.Errorf("%s lacks an address, public key or endpoint for peers", instance)
	}
	endpoint := info.Endpoint
	if !strings.Contains(endpoint, ":") {
		endpoint += ":" + server.String("port")
	}
	allowed := splitList(info.AllowedIPs)
	if len(allowed) == 0 {
		if allowed, err = networks(server.String("tunneladdress")); err != nil {
			return nil, err
		}
	}

	body := map[string]any{"client": map[string]string{
		"enabled": "1", "name": name, "pubkey": r.PublicKey, "psk": r.PresharedKey,
		"tunneladdress": info.Address, "servers": uuid,
	}}
	var out struct {
		Result      string          `json:"result"`
		UUID        string          `json:"uuid"`
		Validations json.RawMessage `json:"validations"`
	}
	if err := c.call(http.MethodPost, "wireguard/client/add_client", body, &out); err != nil {
		return nil, err
	}
	if out.Result != "saved" || out.UUID == "" {
		return nil, fmt.Errorf("adding the peer failed: %s", string(out.Validations))
	}
	var reconfigured struct {
		Result string `json:"result"`
	}
	if err := c.call(http.MethodPost, "wireguard/service/reconfigure", struct{}{}, &reconfigured); err != nil || reconfigured.Result != "ok" {
		return nil, fmt.Errorf("peer %s was added but WireGuard on %s did not reconfigure", out.UUID, c.url)
	}
	return &ca.Peer{
		ID:         out.UUID,
		Address:    splitList(info.Address),
		PublicKey:  info.PubKey,
		Endpoint:   endpoint,
		AllowedIPs: allowed,
	}, nil
}

func (c *Client) String() string {
	return c.url
}
