package devicefile

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string {
	return e.Kind + ": " + e.Msg
}

func valueError(format string, args ...any) error {
	return &Error{"ValueError", fmt.Sprintf(format, args...)}
}

func keyError(key string) error {
	return &Error{"KeyError", "'" + key + "'"}
}

type Unit struct {
	Name    string
	Content string
}

type Units struct {
	Files  []Unit
	Enable []string
	Start  []string
}

type Clone struct {
	URL  string
	Dest string
	Ref  string
}

type User struct {
	Name           string
	Shell          string
	AuthorizedKeys []string
	Env            []string
	GitClone       []Clone
	Systemd        Units
}

type PKIFile struct {
	Name string
	PEM  string
}

type K8s struct {
	Conf []string
	PKI  []PKIFile
}

type Config struct {
	User           string
	Hostname       string
	Timezone       string
	Roles          []string
	AuthorizedKeys []string
	Users          []User
	SystemUnits    Units
	UserUnits      Units
	WGNetdev       []string
	WGNetwork      []string
	K8s            *K8s
}

var (
	reUserName  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reTimezone  = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`)
	reRole      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	reShell     = regexp.MustCompile(`^[A-Za-z0-9_./+-]+$`)
	reEnvName   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	reCloneURL  = regexp.MustCompile(`^(?:(https|ssh|git)://[^/]+/|[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:)`)
	reUnitName  = regexp.MustCompile(`^([A-Za-z0-9:_\\-][A-Za-z0-9:_.\\-]*(?:@[A-Za-z0-9:_.\\-]*)?\.(?:service|socket|timer|path|target|mount|automount|swap|slice))(\.d/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.conf)?$`)
	reSection   = regexp.MustCompile(`(?m)^\[[A-Za-z]+\][ \t]*$`)
	reInstall   = regexp.MustCompile(`(?m)^\[Install\][ \t]*$`)
	reCluster   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	reHost      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	reMethod    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	reToken     = regexp.MustCompile(`^[a-z0-9]{6}\.[a-z0-9]{16}$`)
	reCAHash    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	rePEMBlock  = regexp.MustCompile(`^\s*-----BEGIN [A-Z0-9 ]+-----\n[A-Za-z0-9+/=\n]+-----END [A-Z0-9 ]+-----\s*$`)
	k8sPKIFiles = []PKIFile{
		{"ca_crt", "ca.crt"}, {"ca_key", "ca.key"},
		{"front_proxy_ca_crt", "front-proxy-ca.crt"}, {"front_proxy_ca_key", "front-proxy-ca.key"},
		{"etcd_ca_crt", "etcd/ca.crt"}, {"etcd_ca_key", "etcd/ca.key"},
		{"sa_key", "sa.key"}, {"sa_pub", "sa.pub"},
	}
)

type table struct {
	path   string
	values map[string]any
	keys   []string
}

type parser struct {
	order map[string][]string
}

func Parse(data []byte) (*Config, error) {
	var raw map[string]any
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, &Error{"TOMLDecodeError", err.Error()}
	}
	p := &parser{order: map[string][]string{}}
	seen := map[string]bool{}
	for _, key := range md.Keys() {
		for i := 1; i <= len(key); i++ {
			parent := strings.Join(key[:i-1], "\x00")
			child := strings.Join(key[:i], "\x00")
			if !seen[child] {
				seen[child] = true
				p.order[parent] = append(p.order[parent], key[i-1])
			}
		}
	}
	return p.config(p.root(raw))
}

func (p *parser) root(values map[string]any) table {
	return p.wrap("", values)
}

func (p *parser) wrap(path string, values map[string]any) table {
	t := table{path: path, values: values}
	known := map[string]bool{}
	for _, k := range p.order[path] {
		if _, ok := values[k]; ok && !known[k] {
			t.keys = append(t.keys, k)
			known[k] = true
		}
	}
	var rest []string
	for k := range values {
		if !known[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	t.keys = append(t.keys, rest...)
	return t
}

func (p *parser) table(parent table, key, what string) (table, error) {
	v, ok := parent.values[key]
	if !ok {
		return table{values: map[string]any{}}, nil
	}
	return p.asTable(v, join(parent.path, key), what)
}

func (p *parser) asTable(v any, path, what string) (table, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return table{}, valueError("%s must be a table", what)
	}
	return p.wrap(path, m), nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "\x00" + key
}

func value(v any, what string) (string, error) {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case int64:
		s = strconv.FormatInt(x, 10)
	default:
		return "", valueError("%s must be a string or number", what)
	}
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "\n\r") {
		return "", valueError("%s must be a single non-empty line", what)
	}
	return s, nil
}

func list(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case []map[string]any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = x[i]
		}
		return out, true
	}
	return nil, false
}

func values(v any, what string) ([]string, error) {
	items, ok := list(v)
	if !ok {
		return nil, valueError("%s must be a list", what)
	}
	var out []string
	for _, item := range items {
		s, err := value(item, what)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func optional(t table, key string, def any) any {
	if v, ok := t.values[key]; ok {
		return v
	}
	return def
}

func required(t table, key string) (any, error) {
	v, ok := t.values[key]
	if !ok {
		return nil, keyError(key)
	}
	return v, nil
}

func (p *parser) config(root table) (*Config, error) {
	c := &Config{}

	system, err := p.table(root, "system", "system")
	if err != nil {
		return nil, err
	}
	if v, ok := system.values["user"]; ok {
		if c.User, err = value(v, "system.user"); err != nil {
			return nil, err
		}
		if !reUserName.MatchString(c.User) {
			return nil, valueError("system.user must be a lowercase user name")
		}
	}
	if v, ok := system.values["hostname"]; ok {
		if c.Hostname, err = value(v, "system.hostname"); err != nil {
			return nil, err
		}
	}
	if v, ok := system.values["timezone"]; ok {
		if c.Timezone, err = value(v, "system.timezone"); err != nil {
			return nil, err
		}
		if !reTimezone.MatchString(c.Timezone) {
			return nil, valueError("system.timezone must be a zone name like Europe/Berlin")
		}
	}
	if c.Roles, err = values(optional(system, "roles", []any{}), "system.roles"); err != nil {
		return nil, err
	}
	for _, role := range c.Roles {
		if !reRole.MatchString(role) {
			return nil, valueError("system.roles must be lowercase role names")
		}
	}

	ssh, err := p.table(root, "ssh", "ssh")
	if err != nil {
		return nil, err
	}
	if c.AuthorizedKeys, err = values(optional(ssh, "authorized_keys", []any{}), "ssh.authorized_keys"); err != nil {
		return nil, err
	}

	users, err := p.table(root, "users", "users")
	if err != nil {
		return nil, err
	}
	for _, name := range users.keys {
		u, err := p.user(users, name)
		if err != nil {
			return nil, err
		}
		c.Users = append(c.Users, u)
	}

	if c.SystemUnits, err = p.units(root, "systemd-system", "systemd-system", true); err != nil {
		return nil, err
	}
	if c.UserUnits, err = p.units(root, "systemd-user", "systemd-user", false); err != nil {
		return nil, err
	}

	if err := p.wg(root, c); err != nil {
		return nil, err
	}
	if err := p.k8s(root, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (p *parser) user(users table, name string) (User, error) {
	u := User{Name: name}
	if !reUserName.MatchString(name) {
		return u, valueError("users.%s: not a lowercase user name", name)
	}
	t, err := p.asTable(users.values[name], join(users.path, name), "users."+name)
	if err != nil {
		return u, err
	}
	if v, ok := t.values["shell"]; ok {
		if u.Shell, err = value(v, "users."+name+".shell"); err != nil {
			return u, err
		}
		if !reShell.MatchString(u.Shell) || strings.Contains(u.Shell, "..") {
			return u, valueError("users.%s.shell must be a shell name or path", name)
		}
	}
	if u.AuthorizedKeys, err = values(optional(t, "authorized_keys", []any{}), "users."+name+".authorized_keys"); err != nil {
		return u, err
	}
	env, err := p.table(t, "env", "users."+name+".env")
	if err != nil {
		return u, err
	}
	for _, k := range env.keys {
		if !reEnvName.MatchString(k) {
			return u, valueError("users.%s.env: %s is not a variable name", name, k)
		}
		v, err := value(env.values[k], "users."+name+".env."+k)
		if err != nil {
			return u, err
		}
		u.Env = append(u.Env, k+"="+v)
	}
	clones, ok := list(optional(t, "git-clone", []any{}))
	if !ok {
		return u, valueError("users.%s.git-clone must be a list", name)
	}
	what := "users." + name + ".git-clone"
	for _, item := range clones {
		if s, ok := item.(string); ok {
			item = map[string]any{"url": s}
		}
		ct, err := p.asTable(item, "", what)
		if err != nil {
			return u, err
		}
		clone, err := gitClone(ct, what)
		if err != nil {
			return u, err
		}
		u.GitClone = append(u.GitClone, clone)
	}
	if u.Systemd, err = p.units(t, "systemd", "users."+name+".systemd", false); err != nil {
		return u, err
	}
	return u, nil
}

func gitClone(t table, what string) (Clone, error) {
	var c Clone
	raw, err := required(t, "url")
	if err != nil {
		return c, err
	}
	if c.URL, err = value(raw, what+".url"); err != nil {
		return c, err
	}
	if !reCloneURL.MatchString(c.URL) {
		return c, valueError("%s: %s is not an https, ssh or git URL", what, c.URL)
	}
	parts := regexp.MustCompile(`[/:]`).Split(strings.TrimRight(c.URL, "/"), -1)
	repo := strings.TrimSuffix(parts[len(parts)-1], ".git")
	if c.Dest, err = value(optional(t, "dest", "~/src/"+repo), what+".dest"); err != nil {
		return c, err
	}
	if !(strings.HasPrefix(c.Dest, "~/") || strings.HasPrefix(c.Dest, "/")) {
		return c, valueError("%s.dest must start with ~/ or / and not contain ..", what)
	}
	for _, part := range strings.Split(c.Dest, "/") {
		if part == ".." {
			return c, valueError("%s.dest must start with ~/ or / and not contain ..", what)
		}
	}
	if v, ok := t.values["ref"]; ok {
		if c.Ref, err = value(v, what+".ref"); err != nil {
			return c, err
		}
	}
	if strings.Contains(c.URL+c.Dest+c.Ref, "\t") {
		return c, valueError("%s must not contain tabs", what)
	}
	return c, nil
}

func (p *parser) units(parent table, key, what string, canStart bool) (Units, error) {
	var out Units
	section, err := p.table(parent, key, what)
	if err != nil {
		return out, err
	}
	for _, name := range section.keys {
		where := what + `."` + name + `"`
		m := reUnitName.FindStringSubmatch(name)
		if m == nil {
			return out, valueError("%s: not a unit name or <unit>.d/<name>.conf", where)
		}
		dropin := m[2] != ""
		unit, err := p.asTable(section.values[name], join(section.path, name), where)
		if err != nil {
			return out, err
		}
		raw, err := required(unit, "content")
		if err != nil {
			return out, err
		}
		content, ok := raw.(string)
		if !ok || !reSection.MatchString(content) {
			return out, valueError("%s.content must be a unit file", where)
		}
		installable := reInstall.MatchString(content)
		on := optional(unit, "enable", installable && !dropin)
		if _, ok := unit.values["start"]; ok && !canStart {
			return out, valueError("%s.start: user units start with the user's systemd", where)
		}
		run := any(false)
		if canStart {
			run = optional(unit, "start", on)
		}
		enable, ok := on.(bool)
		if !ok {
			return out, valueError("%s.enable must be true or false", where)
		}
		start, ok := run.(bool)
		if !ok {
			return out, valueError("%s.start must be true or false", where)
		}
		if dropin && (enable || start) {
			return out, valueError("%s: a drop-in is not enabled or started, its unit is", where)
		}
		if enable && !installable {
			return out, valueError("%s.enable needs an [Install] section", where)
		}
		out.Files = append(out.Files, Unit{name, strings.Trim(content, "\n") + "\n"})
		if enable {
			out.Enable = append(out.Enable, name)
		}
		if start {
			out.Start = append(out.Start, name)
		}
	}
	return out, nil
}

func (p *parser) wg(root table, c *Config) error {
	wg, err := p.table(root, "wg", "wg")
	if err != nil || len(wg.values) == 0 {
		return err
	}
	raw, err := required(wg, "private_key")
	if err != nil {
		return err
	}
	key, err := value(raw, "wg.private_key")
	if err != nil {
		return err
	}
	netdev := []string{"[NetDev]", "Name=wg0", "Kind=wireguard", "", "[WireGuard]", "PrivateKey=" + key, "RouteTable=main"}
	if v, ok := wg.values["listen_port"]; ok {
		port, err := value(v, "wg.listen_port")
		if err != nil {
			return err
		}
		netdev = append(netdev, "ListenPort="+port)
	}
	peers, ok := list(optional(wg, "peer", []any{}))
	if !ok {
		return valueError("wg.peer must be an array of tables")
	}
	for _, item := range peers {
		peer, err := p.asTable(item, "", "wg.peer")
		if err != nil {
			return err
		}
		raw, err := required(peer, "public_key")
		if err != nil {
			return err
		}
		pub, err := value(raw, "wg.peer.public_key")
		if err != nil {
			return err
		}
		netdev = append(netdev, "", "[WireGuardPeer]", "PublicKey="+pub)
		for _, opt := range [][2]string{{"preshared_key", "PresharedKey"}, {"endpoint", "Endpoint"}, {"persistent_keepalive", "PersistentKeepalive"}} {
			if v, ok := peer.values[opt[0]]; ok {
				s, err := value(v, "wg.peer."+opt[0])
				if err != nil {
					return err
				}
				netdev = append(netdev, opt[1]+"="+s)
			}
		}
		ips, err := values(optional(peer, "allowed_ips", []any{}), "wg.peer.allowed_ips")
		if err != nil {
			return err
		}
		for _, ip := range ips {
			netdev = append(netdev, "AllowedIPs="+ip)
		}
	}
	network := []string{"[Match]", "Name=wg0", "", "[Link]", "ActivationPolicy=manual", "", "[Network]"}
	addrs, err := values(optional(wg, "address", []any{}), "wg.address")
	if err != nil {
		return err
	}
	for _, a := range addrs {
		network = append(network, "Address="+a)
	}
	c.WGNetdev, c.WGNetwork = netdev, network
	return nil
}

func network(s, what string) (string, error) {
	v, err := value(s, what)
	if err != nil {
		return "", err
	}
	if !strings.Contains(v, "/") {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return "", valueError("'%s' does not appear to be an IPv4 or IPv6 network", v)
		}
		v += "/" + strconv.Itoa(addr.BitLen())
	}
	prefix, err := netip.ParsePrefix(v)
	if err != nil {
		return "", valueError("'%s' does not appear to be an IPv4 or IPv6 network", v)
	}
	if prefix.Masked() != prefix {
		return "", valueError("%s has host bits set", v)
	}
	return prefix.String(), nil
}

func (p *parser) k8s(root table, c *Config) error {
	k8s, err := p.table(root, "k8s", "k8s")
	if err != nil {
		return err
	}
	var roles []string
	for _, r := range c.Roles {
		if r == "k8s-master" || r == "k8s-client" {
			roles = append(roles, r)
		}
	}
	if len(roles) > 1 {
		return valueError("a node is either k8s-master or k8s-client")
	}
	if len(roles) == 1 && len(k8s.values) == 0 {
		return valueError("role %s needs a [k8s] section", roles[0])
	}
	if len(k8s.values) == 0 {
		return nil
	}
	master := len(roles) == 1 && roles[0] == "k8s-master"

	raw, err := required(k8s, "cluster")
	if err != nil {
		return err
	}
	cluster, err := value(raw, "k8s.cluster")
	if err != nil {
		return err
	}
	if !reCluster.MatchString(cluster) {
		return valueError("k8s.cluster must be a short lowercase name")
	}
	endpoint, err := value(optional(k8s, "endpoint", cluster+".k8s.internal:6443"), "k8s.endpoint")
	if err != nil {
		return err
	}
	host, port := "", endpoint
	if i := strings.LastIndex(endpoint, ":"); i >= 0 {
		host, port = endpoint[:i], endpoint[i+1:]
	}
	n, perr := strconv.Atoi(port)
	if !reHost.MatchString(host) || perr != nil || strings.ContainsAny(port, "+-") || n <= 0 || n >= 65536 {
		return valueError("k8s.endpoint must be host:port")
	}
	method, err := value(optional(k8s, "endpoint_method", "mdns"), "k8s.endpoint_method")
	if err != nil {
		return err
	}
	if !reMethod.MatchString(method) {
		return valueError("k8s.endpoint_method must be a lowercase name")
	}
	if raw, err = required(k8s, "token"); err != nil {
		return err
	}
	token, err := value(raw, "k8s.token")
	if err != nil {
		return err
	}
	if !reToken.MatchString(token) {
		return valueError("k8s.token must be a kubeadm bootstrap token")
	}
	if raw, err = required(k8s, "ca_cert_hash"); err != nil {
		return err
	}
	hash, err := value(raw, "k8s.ca_cert_hash")
	if err != nil {
		return err
	}
	if !reCAHash.MatchString(hash) {
		return valueError("k8s.ca_cert_hash must be sha256:<64 hex>")
	}
	var pod, service string
	for _, cidr := range []struct {
		key, def string
		out      *string
	}{{"pod_cidr", "10.244.0.0/16", &pod}, {"service_cidr", "10.96.0.0/12", &service}} {
		v, err := value(optional(k8s, cidr.key, cidr.def), "k8s."+cidr.key)
		if err != nil {
			return err
		}
		if *cidr.out, err = network(v, "k8s."+cidr.key); err != nil {
			return err
		}
	}
	bootstrap, ok := optional(k8s, "bootstrap", false).(bool)
	if !ok {
		return valueError("k8s.bootstrap must be true or false")
	}
	if bootstrap && !master {
		return valueError("k8s.bootstrap is for a k8s-master")
	}
	pki, err := p.table(k8s, "pki", "k8s.pki")
	if err != nil {
		return err
	}
	if len(pki.values) > 0 && !master {
		return valueError("k8s.pki is for a k8s-master, a client must not carry the cluster CA key")
	}
	out := &K8s{}
	if master {
		var missing []string
		for _, f := range k8sPKIFiles {
			if _, ok := pki.values[f.Name]; !ok {
				missing = append(missing, f.Name)
			}
		}
		if len(missing) > 0 {
			return valueError("k8s.pki lacks %s", strings.Join(missing, ", "))
		}
		for _, f := range k8sPKIFiles {
			pem, ok := pki.values[f.Name].(string)
			if !ok || !rePEMBlock.MatchString(pem) {
				return valueError("k8s.pki.%s must be one PEM block", f.Name)
			}
			out.PKI = append(out.PKI, PKIFile{f.PEM, strings.TrimSpace(pem)})
		}
	}
	role := ""
	if len(roles) == 1 {
		role = roles[0][4:]
	}
	yes := "no"
	if bootstrap {
		yes = "yes"
	}
	out.Conf = []string{
		"K8S_ROLE=" + role,
		"K8S_CLUSTER=" + cluster,
		"K8S_ENDPOINT=" + endpoint,
		"K8S_ENDPOINT_HOST=" + host,
		"K8S_ENDPOINT_METHOD=" + method,
		"K8S_TOKEN=" + token,
		"K8S_CA_CERT_HASH=" + hash,
		"K8S_POD_CIDR=" + pod,
		"K8S_SERVICE_CIDR=" + service,
		"K8S_BOOTSTRAP=" + yes,
	}
	c.K8s = out
	return nil
}

func put(dir, name string, lines []string) error {
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func putUnits(dir, dest string, u Units) error {
	for _, f := range u.Files {
		path := filepath.Join(dir, dest, f.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(f.Content), 0o600); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(u.Files))
	for _, f := range u.Files {
		names = append(names, f.Name)
	}
	for _, list := range []struct {
		suffix string
		names  []string
	}{{"files", names}, {"enable", u.Enable}, {"start", u.Start}} {
		if len(list.names) > 0 {
			if err := put(dir, dest+"."+list.suffix, list.names); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) WriteOut(dir string) error {
	var steps []func() error
	add := func(name string, lines []string, when bool) {
		if when {
			steps = append(steps, func() error { return put(dir, name, lines) })
		}
	}
	add("user", []string{c.User}, c.User != "")
	add("hostname", []string{c.Hostname}, c.Hostname != "")
	add("timezone", []string{c.Timezone}, c.Timezone != "")
	add("roles", c.Roles, len(c.Roles) > 0)
	add("authorized_keys", c.AuthorizedKeys, len(c.AuthorizedKeys) > 0)
	for _, u := range c.Users {
		u := u
		base := "users/" + u.Name + "/"
		add(base+"present", []string{u.Name}, true)
		add(base+"shell", []string{u.Shell}, u.Shell != "")
		add(base+"authorized_keys", u.AuthorizedKeys, len(u.AuthorizedKeys) > 0)
		add(base+"env", u.Env, len(u.Env) > 0)
		var rows []string
		for _, cl := range u.GitClone {
			rows = append(rows, cl.URL+"\t"+cl.Dest+"\t"+cl.Ref)
		}
		add(base+"git-clone", rows, len(rows) > 0)
		steps = append(steps, func() error { return putUnits(dir, base+"systemd", u.Systemd) })
	}
	steps = append(steps,
		func() error { return putUnits(dir, "systemd-system", c.SystemUnits) },
		func() error { return putUnits(dir, "systemd-user", c.UserUnits) })
	add("wg0.netdev", c.WGNetdev, c.WGNetdev != nil)
	add("wg0.network", c.WGNetwork, c.WGNetwork != nil)
	if c.K8s != nil {
		for _, f := range c.K8s.PKI {
			add("k8s-pki/"+f.Name, []string{f.PEM}, true)
		}
		add("k8s.conf", c.K8s.Conf, true)
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}
