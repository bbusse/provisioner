package apply

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bbusse/provisioner/internal/devicefile"
)

type Applier struct {
	Root   string
	Stdout io.Writer
	Stderr io.Writer
	failed bool
}

func (a *Applier) say(format string, args ...any) {
	fmt.Fprintf(a.Stdout, "provision: "+format+"\n", args...)
}

func (a *Applier) warn(format string, args ...any) {
	fmt.Fprintf(a.Stderr, "provision: "+format+"\n", args...)
}

func (a *Applier) fail(format string, args ...any) {
	a.warn(format, args...)
	a.failed = true
}

func (a *Applier) path(p string) string {
	return filepath.Join(a.Root, p)
}

func (a *Applier) run(name string, args ...string) bool {
	cmd := exec.Command(name, args...)
	cmd.Stdout = a.Stdout
	cmd.Stderr = a.Stderr
	return cmd.Run() == nil
}

func (a *Applier) quiet(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

func output(name string, args ...string) string {
	out, _ := exec.Command(name, args...).Output()
	return strings.TrimRight(string(out), "\n")
}

func ids(name, group string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(g.Gid)
	return uid, gid, nil
}

func installDir(path string, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return os.Lchown(path, uid, gid)
}

func installFile(path string, data []byte, mode os.FileMode, uid, gid int, parents bool) error {
	if parents {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".provision"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chown(tmp, uid, gid); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func lines(items []string) []byte {
	return []byte(strings.Join(items, "\n") + "\n")
}

func mergeKeys(path string, keys []string, uid, gid int) error {
	current, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	set := map[string]bool{}
	for _, l := range strings.Split(string(current), "\n") {
		set[l] = true
	}
	for _, k := range keys {
		set[k] = true
	}
	delete(set, "")
	var all []string
	for k := range set {
		all = append(all, k)
	}
	sort.Strings(all)
	if err := os.WriteFile(path, lines(all), 0o600); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func (a *Applier) Apply(c *devicefile.Config, imageUser string) bool {
	userName := imageUser
	if c.User != "" {
		userName = a.renameUser(imageUser, c.User)
	}
	if c.Hostname != "" {
		a.hostname(c.Hostname)
	}
	if c.Timezone != "" {
		a.timezone(c.Timezone)
	}
	if len(c.AuthorizedKeys) > 0 {
		a.imageUserKeys(userName, c.AuthorizedKeys)
	}
	a.users(c.Users)
	if c.WGNetdev != nil {
		a.wireguard(c)
	}
	if c.K8s != nil {
		a.k8s(c.K8s)
	}
	a.units(c)
	a.roles(c.Roles)
	return !a.failed
}

func (a *Applier) renameUser(old, new string) string {
	if new == old {
		return old
	}
	if a.quiet("id", new) {
		a.fail("user %s already exists, not renaming %s", new, old)
		return old
	}
	if !a.run("usermod", "-l", new, "-d", "/home/"+new, "-m", old) {
		a.fail("could not rename user %s to %s", old, new)
		return old
	}
	if a.quiet("getent", "group", old) {
		a.run("groupmod", "-n", new, old)
	}
	dropins, _ := filepath.Glob(a.path("/etc/systemd/system/*.service.d/user.conf"))
	for _, f := range dropins {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			if l == "User="+old {
				os.WriteFile(f, []byte(fmt.Sprintf("[Service]\nUser=%s\nEnvironmentFile=-/home/%s/.config/environment.d/50-provision.conf\n", new, new)), 0o644)
				break
			}
		}
	}
	var waiting []string
	wants, _ := filepath.Glob(a.path("/etc/systemd/system/*.wants/*@" + old + ".service"))
	for _, l := range wants {
		info, err := os.Lstat(l)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, err := os.Readlink(l)
		if err != nil {
			continue
		}
		renamed := l[:strings.LastIndex(l, "@")] + "@" + new + ".service"
		os.Remove(renamed)
		os.Symlink(target, renamed)
		os.Remove(l)
		u := filepath.Base(l)
		if output("systemctl", "show", "-P", "ActiveState", u) == "inactive" &&
			strings.TrimSpace(output("systemctl", "list-jobs", "--no-legend", u)) != "" {
			waiting = append(waiting, u)
		}
	}
	a.run("systemctl", "daemon-reload")
	for _, u := range waiting {
		a.run("systemctl", "--no-block", "stop", u)
		a.run("systemctl", "--no-block", "start", u[:strings.LastIndex(u, "@")]+"@"+new+".service")
	}
	a.say("renamed user %s to %s", old, new)
	return new
}

func (a *Applier) hostname(name string) {
	previous := output("uname", "-n")
	if !a.run("hostnamectl", "set-hostname", name) {
		a.fail("could not set hostname %s", name)
		return
	}
	a.say("hostname %s", name)
	if previous == name {
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(output("networkctl", "list", "--no-legend")))
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 5 || (f[2] != "ether" && f[2] != "wlan") || f[4] != "configured" {
			continue
		}
		if a.run("networkctl", "reconfigure", f[1]) {
			a.say("reconfigured %s, DHCP carries the new hostname", f[1])
		} else {
			a.warn("could not reconfigure %s", f[1])
		}
	}
}

func (a *Applier) timezone(tz string) {
	info, err := os.Stat(a.path("/usr/share/zoneinfo/" + tz))
	if err != nil || !info.Mode().IsRegular() {
		a.fail("unknown timezone %s", tz)
		return
	}
	if !a.run("timedatectl", "set-timezone", tz) {
		a.fail("could not set timezone %s", tz)
		return
	}
	a.say("timezone %s", tz)
}

func (a *Applier) imageUserKeys(name string, keys []string) {
	uid, gid, err := ids(name, name)
	if err == nil {
		dir := a.path("/home/" + name + "/.ssh")
		if err = installDir(dir, 0o700, uid, gid); err == nil {
			err = mergeKeys(filepath.Join(dir, "authorized_keys"), keys, uid, gid)
		}
	}
	if err != nil {
		a.fail("could not install ssh keys for %s: %v", name, err)
		return
	}
	a.say("installed ssh keys for %s", name)
}

func (a *Applier) shellPath(shell string) string {
	if strings.HasPrefix(shell, "/") {
		return shell
	}
	data, _ := os.ReadFile(a.path("/etc/shells"))
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		if filepath.Base(l) == shell || l == shell {
			return l
		}
	}
	return ""
}

func listed(path, line string) bool {
	data, _ := os.ReadFile(path)
	for _, l := range strings.Split(string(data), "\n") {
		if l == line {
			return true
		}
	}
	return false
}

func (a *Applier) users(users []devicefile.User) {
	sorted := append([]devicefile.User(nil), users...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	clones := false
	for _, u := range sorted {
		name := u.Name
		if !a.quiet("id", name) {
			if !a.run("useradd", "-m", "-U", "-G", "wheel", name) {
				a.fail("could not create user %s", name)
				continue
			}
			a.say("created user %s", name)
		}
		account, err := user.Lookup(name)
		if err != nil {
			a.fail("no user %s: %v", name, err)
			continue
		}
		group, err := user.LookupGroupId(account.Gid)
		if err != nil {
			a.fail("no group for %s: %v", name, err)
			continue
		}
		home := a.path(account.HomeDir)
		uid, _ := strconv.Atoi(account.Uid)
		gid, _ := strconv.Atoi(group.Gid)

		if u.Shell != "" {
			path := a.shellPath(u.Shell)
			info, err := os.Stat(path)
			if path != "" && err == nil && info.Mode()&0o111 != 0 && listed(a.path("/etc/shells"), path) &&
				a.run("usermod", "-s", path, name) {
				a.say("shell of %s is %s", name, path)
			} else {
				a.fail("shell %s is not installed or not in /etc/shells, %s keeps its shell", u.Shell, name)
			}
		}
		if len(u.AuthorizedKeys) > 0 {
			dir := filepath.Join(home, ".ssh")
			err := installDir(dir, 0o700, uid, gid)
			if err == nil {
				err = mergeKeys(filepath.Join(dir, "authorized_keys"), u.AuthorizedKeys, uid, gid)
			}
			if err != nil {
				a.fail("could not install ssh keys for %s: %v", name, err)
			} else {
				a.say("installed ssh keys for %s", name)
			}
		}
		if len(u.Env) > 0 {
			err := installDir(filepath.Join(home, ".config"), 0o755, uid, gid)
			if err == nil {
				err = installDir(filepath.Join(home, ".config", "environment.d"), 0o755, uid, gid)
			}
			if err == nil {
				err = installFile(filepath.Join(home, ".config", "environment.d", "50-provision.conf"), lines(u.Env), 0o644, uid, gid, false)
			}
			if err != nil {
				a.fail("could not write the environment for %s: %v", name, err)
			} else {
				a.say("environment for %s", name)
			}
		}
		if len(u.GitClone) > 0 {
			var b bytes.Buffer
			for _, c := range u.GitClone {
				fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", name, c.URL, c.Dest, c.Ref)
			}
			os.MkdirAll(a.path("/var/lib/provision"), 0o755)
			f, err := os.OpenFile(a.path("/var/lib/provision/git-clone"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err == nil {
				_, err = f.Write(b.Bytes())
				f.Close()
			}
			if err != nil {
				a.fail("could not queue clones for %s: %v", name, err)
			}
			clones = true
		}
		if len(u.Systemd.Files) > 0 {
			unitDir := filepath.Join(home, ".config", "systemd", "user")
			for _, d := range []string{filepath.Join(home, ".config"), filepath.Join(home, ".config", "systemd"), unitDir} {
				installDir(d, 0o755, uid, gid)
			}
			for _, f := range u.Systemd.Files {
				if strings.Contains(f.Name, "/") {
					installDir(filepath.Join(unitDir, filepath.Dir(f.Name)), 0o755, uid, gid)
				}
				if err := installFile(filepath.Join(unitDir, f.Name), []byte(f.Content), 0o644, uid, gid, false); err != nil {
					a.fail("could not install systemd user unit %s for %s", f.Name, name)
				} else {
					a.say("systemd user unit %s for %s", f.Name, name)
				}
			}
		}
		for _, unit := range u.Systemd.Enable {
			if a.run("runuser", "-u", name, "--", "env", "HOME="+account.HomeDir, "systemctl", "--user", "--root=/", "enable", unit) {
				a.say("enabled %s for %s", unit, name)
			} else {
				a.fail("could not enable %s for %s", unit, name)
			}
		}
	}
	if clones {
		a.run("systemctl", "--no-block", "start", "provision-git-clone.service")
		a.say("cloning in provision-git-clone.service")
	}
}

func (a *Applier) wireguard(c *devicefile.Config) {
	gid := 0
	if g, err := user.LookupGroup("systemd-network"); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	for _, f := range []struct {
		name  string
		lines []string
	}{{"wg0.netdev", c.WGNetdev}, {"wg0.network", c.WGNetwork}} {
		if err := installFile(a.path("/etc/systemd/network/"+f.name), lines(f.lines), 0o640, 0, gid, false); err != nil {
			a.fail("could not install %s: %v", f.name, err)
		}
	}
	if !a.quiet("networkctl", "reload") {
		a.quiet("systemctl", "reload", "systemd-networkd")
	}
	a.say("installed WireGuard config")
}

func (a *Applier) k8s(k *devicefile.K8s) {
	os.MkdirAll(a.path("/etc/provision"), 0o755)
	if err := installFile(a.path("/etc/provision/k8s.conf"), lines(k.Conf), 0o600, 0, 0, false); err != nil {
		a.fail("could not install the k8s configuration: %v", err)
	}
	if len(k.PKI) > 0 {
		dir := a.path("/etc/provision/k8s-pki")
		os.RemoveAll(dir)
		os.MkdirAll(filepath.Join(dir, "etcd"), 0o755)
		os.Chmod(dir, 0o700)
		for _, f := range k.PKI {
			if err := installFile(filepath.Join(dir, f.Name), []byte(f.PEM+"\n"), 0o600, 0, 0, false); err != nil {
				a.fail("could not install %s: %v", f.Name, err)
			}
		}
	}
	cluster := ""
	for _, l := range k.Conf {
		if v, ok := strings.CutPrefix(l, "K8S_CLUSTER="); ok {
			cluster = v
		}
	}
	a.say("installed the k8s configuration for cluster %s", cluster)
}

func (a *Applier) units(c *devicefile.Config) {
	for _, scope := range []struct {
		name  string
		units devicefile.Units
	}{{"system", c.SystemUnits}, {"user", c.UserUnits}} {
		for _, f := range scope.units.Files {
			if err := installFile(a.path("/etc/systemd/"+scope.name+"/"+f.Name), []byte(f.Content), 0o644, 0, 0, true); err != nil {
				a.fail("could not install systemd %s unit %s", scope.name, f.Name)
			} else {
				a.say("systemd %s unit %s", scope.name, f.Name)
			}
		}
	}
	if len(c.SystemUnits.Files) > 0 && !a.run("systemctl", "daemon-reload") {
		a.failed = true
	}
	for _, step := range []struct {
		units []string
		args  []string
	}{
		{c.SystemUnits.Enable, []string{"enable"}},
		{c.UserUnits.Enable, []string{"--global", "enable"}},
		{c.SystemUnits.Start, []string{"--no-block", "start"}},
	} {
		for _, u := range step.units {
			if a.run("systemctl", append(append([]string(nil), step.args...), u)...) {
				a.say("systemctl %s %s", strings.Join(step.args, " "), u)
			} else {
				a.fail("could not systemctl %s %s", strings.Join(step.args, " "), u)
			}
		}
	}
}

func (a *Applier) roles(roles []string) {
	for _, role := range roles {
		target := "role-" + role + ".target"
		_, errEtc := os.Stat(a.path("/etc/systemd/system/" + target))
		_, errLib := os.Stat(a.path("/usr/lib/systemd/system/" + target))
		switch {
		case errEtc != nil && errLib != nil:
			a.fail("this image has no role %s", role)
		case a.run("systemctl", "enable", target) && a.run("systemctl", "--no-block", "start", target):
			a.say("role %s", role)
		default:
			a.fail("could not enable role %s", role)
		}
	}
}
