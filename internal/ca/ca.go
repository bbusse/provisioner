package ca

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bbusse/provisioner/internal/settings"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("exists already")
)

type Profile string

const (
	ProfileClient Profile = "client"
	ProfileServer Profile = "server"
	ProfileCA     Profile = "ca"
)

type SignRequest struct {
	Name    string
	Profile Profile
	CSR     string
	Days    int
	DNS     []string
	IPs     []string
}

type Signed struct {
	ID  string
	PEM string
}

type PeerRequest struct {
	PublicKey    string
	PresharedKey string
}

type Peer struct {
	ID         string
	Address    []string
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
}

type Backend interface {
	CA(name string) (string, error)
	HasCert(name string) (bool, error)
	Sign(ca string, r SignRequest) (*Signed, error)
	AddPeer(instance, name string, r PeerRequest) (*Peer, error)
	String() string
}

type Factory func(settings.Env) (Backend, error)

var backends = map[string]Factory{}

func Register(name string, f Factory) {
	backends[name] = f
}

func names() string {
	var out []string
	for name := range backends {
		out = append(out, name)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func Open(name string, env settings.Env) (Backend, error) {
	if name == "" {
		return nil, fmt.Errorf("set PROVISIONER_CA to the CA backend, one of: %s", names())
	}
	f, ok := backends[name]
	if !ok {
		return nil, fmt.Errorf("PROVISIONER_CA: no CA backend %s, only %s", name, names())
	}
	return f(env)
}
