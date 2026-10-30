package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/bbusse/provisioner/internal/api"
	"github.com/bbusse/provisioner/internal/fetch"
	"github.com/bbusse/provisioner/internal/jobs"
	"github.com/bbusse/provisioner/internal/mtls"
	_ "github.com/bbusse/provisioner/internal/opnsense"
	"github.com/bbusse/provisioner/internal/profiles"
	"github.com/bbusse/provisioner/internal/provide"
	"github.com/bbusse/provisioner/internal/settings"
)

const usage = `usage: provisioner serve
       provisioner provide [-listen :8443] [-cert FILE] [-key FILE] [-ca FILE] [-dir DIR]
       provisioner fetch USER
       provisioner fetch-profiles
       provisioner signer
       provisioner server NAME [SAN...]
       provisioner device NAME
       provisioner config NAME [-user USER] [-roles ROLE,...] [-timezone ZONE] [-ssh-key KEY]... [-k8s CLUSTER:master|client] [-no-wg]
       provisioner cluster NAME [-endpoint HOST:PORT] [-method mdns|dns] [-pod-cidr CIDR] [-service-cidr CIDR]
       provisioner flux CLUSTER ssh://USER@HOST[:PORT]/PATH
       provisioner k8s DEVICE CLUSTER master|client
       provisioner k8s export DEVICE
       provisioner k8s deploy DEVICE HOST
       provisioner seal [NAME...]
       provisioner open NAME
       provisioner devices
`

type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

type call struct {
	method string
	path   string
	body   any
	local  func(*jobs.Jobs) error
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "provisioner: "+format+"\n", args...)
	os.Exit(1)
}

func parse(cmd string, args []string) (call, error) {
	bad := errors.New(usage)
	switch cmd {
	case "signer":
		if len(args) != 0 {
			return call{}, bad
		}
		return call{"POST", "/v1/signer", nil, func(j *jobs.Jobs) error { return j.Signer() }}, nil
	case "server":
		if len(args) < 1 {
			return call{}, bad
		}
		name, sans := args[0], args[1:]
		return call{"POST", "/v1/servers/" + name, map[string]any{"sans": sans},
			func(j *jobs.Jobs) error { return j.Server(name, sans) }}, nil
	case "device":
		if len(args) != 1 {
			return call{}, bad
		}
		name := args[0]
		return call{"POST", "/v1/devices/" + name, nil, func(j *jobs.Jobs) error { return j.Device(name) }}, nil
	case "config":
		if len(args) < 1 {
			return call{}, bad
		}
		o := jobs.ConfigOptions{Name: args[0]}
		fs := flag.NewFlagSet("config", flag.ContinueOnError)
		var roles string
		var keys repeated
		fs.StringVar(&o.User, "user", "", "")
		fs.StringVar(&roles, "roles", "", "")
		fs.StringVar(&o.Timezone, "timezone", "", "")
		fs.Var(&keys, "ssh-key", "")
		fs.StringVar(&o.K8s, "k8s", "", "")
		fs.BoolVar(&o.NoWG, "no-wg", false, "")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return call{}, bad
		}
		for _, r := range strings.Split(roles, ",") {
			if r = strings.TrimSpace(r); r != "" {
				o.Roles = append(o.Roles, r)
			}
		}
		o.SSHKeys = keys
		return call{"POST", "/v1/devices/" + o.Name + "/config", o, func(j *jobs.Jobs) error { return j.Config(o) }}, nil
	case "cluster":
		if len(args) < 1 {
			return call{}, bad
		}
		o := jobs.ClusterOptions{Name: args[0]}
		fs := flag.NewFlagSet("cluster", flag.ContinueOnError)
		fs.StringVar(&o.Endpoint, "endpoint", "", "")
		fs.StringVar(&o.Method, "method", "", "")
		fs.StringVar(&o.PodCIDR, "pod-cidr", "", "")
		fs.StringVar(&o.ServiceCIDR, "service-cidr", "", "")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return call{}, bad
		}
		return call{"POST", "/v1/clusters/" + o.Name, o, func(j *jobs.Jobs) error { return j.Cluster(o) }}, nil
	case "flux":
		if len(args) != 2 {
			return call{}, bad
		}
		cluster, repo := args[0], args[1]
		return call{"POST", "/v1/clusters/" + cluster + "/flux", map[string]string{"url": repo},
			func(j *jobs.Jobs) error { return j.Flux(cluster, repo) }}, nil
	case "k8s":
		if len(args) != 3 {
			return call{}, bad
		}
		device, cluster, role := args[0], args[1], args[2]
		return call{"POST", "/v1/devices/" + device + "/k8s", map[string]string{"cluster": cluster, "role": role},
			func(j *jobs.Jobs) error { return j.K8s(device, cluster, role) }}, nil
	case "seal":
		names := args
		return call{"POST", "/v1/seal", map[string]any{"names": names}, func(j *jobs.Jobs) error { return j.Seal(names) }}, nil
	case "open":
		if len(args) != 1 {
			return call{}, bad
		}
		name := args[0]
		return call{"POST", "/v1/devices/" + name + "/open", nil, func(j *jobs.Jobs) error { return j.Open(name) }}, nil
	}
	return call{}, bad
}

func serve() {
	s, err := settings.Load()
	if err != nil {
		die("%v", err)
	}
	if s.TLSCert == "" || s.TLSKey == "" {
		die("set PROVISIONER_TLS_CERT and PROVISIONER_TLS_KEY to the server's certificate and key")
	}
	if len(s.Admins) == 0 {
		die("set PROVISIONER_ADMINS to the CNs of the client certificates that may call the API")
	}
	server := &api.Server{Settings: s, NewJobs: jobs.New, Logger: log.New(os.Stderr, "provisioner: ", log.LstdFlags)}
	tlsConfig, err := server.TLSConfig()
	if err != nil {
		die("%v", err)
	}
	httpServer := &http.Server{
		Addr:              s.Listen,
		Handler:           server.Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}
	server.Logger.Printf("listening on %s for %s, data in %s", s.Listen, strings.Join(s.Admins, ", "), s.CertsDir)
	if err := mtls.Serve(httpServer, server.Logger); err != nil {
		die("%v", err)
	}
}

func main() {
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch args[0] {
	case "serve":
		serve()
		return
	// router is the deprecated and undocumented name of provide
	case "provide", "router":
		provide.Run(args[1:])
		return
	case "fetch":
		user := ""
		if len(args) > 1 {
			user = args[1]
		}
		f := &fetch.Fetcher{Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Sleep: time.Sleep}
		os.Exit(f.Run(user))
	case "fetch-profiles":
		os.Exit(fetchProfiles())
	}

	// Jobs run here on the data in PROVISIONER_DATA, or on the daemon at
	// PROVISIONER_URL when that is set
	url := os.Getenv("PROVISIONER_URL")
	if args[0] == "devices" {
		var devices []api.Device
		if url == "" {
			devices = localJobs().Store.List()
		} else if err := newClient(url).Do("GET", "/v1/devices", nil, &devices); err != nil {
			die("%v", err)
		}
		for _, d := range devices {
			fmt.Printf("%-24s plain=%t sealed=%t cert=%t\n", d.Name, d.Plain, d.Sealed, d.Cert)
		}
		return
	}

	// export and deploy hand out the cluster's keys, which the API never
	// does, so they always run here
	if args[0] == "k8s" && len(args) == 3 && args[1] == "export" {
		if err := localJobs().Export(args[2], os.Stdout); err != nil {
			die("%v", err)
		}
		return
	}
	if args[0] == "k8s" && len(args) == 4 && args[1] == "deploy" {
		if err := localJobs().Deploy(args[2], args[3]); err != nil {
			die("%v", err)
		}
		return
	}

	c, err := parse(args[0], args[1:])
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(2)
	}
	if url == "" {
		if err := c.local(localJobs()); err != nil {
			die("%v", err)
		}
		return
	}
	var resp api.Response
	if err := newClient(url).Do(c.method, c.path, c.body, &resp); err != nil {
		die("%v", err)
	}
	for _, line := range resp.Log {
		fmt.Println(line)
	}
	if resp.Error != "" {
		die("%s", resp.Error)
	}
}

func localJobs() *jobs.Jobs {
	s, err := settings.Load()
	if err != nil {
		die("%v", err)
	}
	return jobs.New(s, func(format string, args ...any) { fmt.Printf(format+"\n", args...) })
}

func fetchProfiles() int {
	f := &profiles.Fetcher{
		Root:   os.Getenv("PROVISION_ROOT"),
		Stderr: os.Stderr,
		Config: func(key string) string {
			out, _ := exec.Command("uci", "-q", "get", "provision.main."+key).Output()
			return strings.TrimSpace(string(out))
		},
		Exec: func(name string, args ...string) error {
			return exec.Command(name, args...).Run()
		},
		Chown: func(path, owner string) error {
			name, group, _ := strings.Cut(owner, ":")
			u, err := user.Lookup(name)
			if err != nil {
				return err
			}
			g, err := user.LookupGroup(group)
			if err != nil {
				return err
			}
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(g.Gid)
			return os.Chown(path, uid, gid)
		},
		Log: func(msg string) {
			exec.Command("logger", "-t", "fetch-profiles", msg).Run()
		},
		Client: &http.Client{Timeout: 2 * time.Minute},
	}
	return f.Run()
}

func newClient(url string) *api.Client {
	client, err := api.NewClient(url, os.Getenv("PROVISIONER_CERT"), os.Getenv("PROVISIONER_KEY"), os.Getenv("PROVISIONER_SERVER_CA"))
	if err != nil {
		die("%v", err)
	}
	return client
}
