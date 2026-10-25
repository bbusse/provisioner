package profiles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Fetcher struct {
	Root   string
	Stderr io.Writer
	Config func(key string) string
	Exec   func(name string, args ...string) error
	Chown  func(path, owner string) error
	Log    func(msg string)
	Client *http.Client
}

var deviceName = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

var githubRepo = regexp.MustCompile(`^https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$`)

type run struct {
	*Fetcher
	changed []string
	rc      int
}

func (f *Fetcher) log(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if f.Log != nil {
		f.Log(msg)
	}
	fmt.Fprintf(f.Stderr, "fetch-profiles: %s\n", msg)
}

func (f *Fetcher) path(p string) string {
	return f.Root + p
}

func (f *Fetcher) Run() int {
	server := f.Config("server")
	switch server {
	case "", "provisioner", "lighttpd":
	default:
		f.log("provision.main.server is %q, not provisioner or lighttpd", server)
		return 1
	}
	if server == "" {
		server = "provisioner"
	}

	src, cleanup, ok := f.source()
	if cleanup != nil {
		defer cleanup()
	}
	if !ok {
		return 0
	}

	r := &run{Fetcher: f}
	if server == "provisioner" {
		r.put(filepath.Join(src, "router/etc/init.d/provisioner"), "/etc/init.d/provisioner", 0o755, "root:root")
	} else {
		r.put(filepath.Join(src, "router/www-provision/cgi-bin/provision"), "/www-provision/cgi-bin/provision", 0o755, "root:root")
		conf := filepath.Join(src, "router/etc/lighttpd/lighttpd.conf")
		if exists(conf) && !same(conf, f.path("/etc/lighttpd/lighttpd.conf")) &&
			f.Exec("lighttpd", "-tt", "-f", conf) != nil {
			f.log("router/etc/lighttpd/lighttpd.conf does not load, keeping the current one")
			r.rc = 1
		} else {
			r.put(conf, "/etc/lighttpd/lighttpd.conf", 0o644, "root:root")
		}
	}
	r.put(filepath.Join(src, "router/etc/umdns/provision.json"), "/etc/umdns/provision.json", 0o644, "root:root")
	r.devices(src)
	r.restart(server)

	if len(r.changed) > 0 {
		f.log("updated %s", strings.Join(r.changed, " "))
	}
	return r.rc
}

func (f *Fetcher) source() (string, func(), bool) {
	if p := f.Config("path"); p != "" {
		if !isDir(filepath.Join(p, "router")) {
			f.log("%s has no router/, keeping the current files", p)
			return "", nil, false
		}
		return p, nil, true
	}

	archive := f.Config("archive")
	if archive == "" {
		repo := f.Config("repo")
		if repo == "" {
			return "", nil, false
		}
		m := githubRepo.FindStringSubmatch(repo)
		if m == nil {
			f.log("cannot tell the archive URL of %s, set provision.main.archive, keeping the current files", repo)
			return "", nil, false
		}
		ref := f.Config("ref")
		if ref == "" {
			ref = "main"
		}
		archive = "https://api.github.com/repos/" + m[1] + "/tarball/" + ref
	}

	tmp, err := os.MkdirTemp("", "fetch-profiles.")
	if err != nil {
		f.log("no temporary directory, keeping the current files")
		return "", nil, false
	}
	cleanup := func() { os.RemoveAll(tmp) }

	req, err := http.NewRequest("GET", archive, nil)
	if err != nil {
		f.log("could not fetch %s, keeping the current files", archive)
		return "", cleanup, false
	}
	if token := f.Config("token"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		f.log("could not fetch %s, keeping the current files", archive)
		return "", cleanup, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		f.log("could not fetch %s: %s, keeping the current files", archive, resp.Status)
		return "", cleanup, false
	}
	top, err := extract(resp.Body, filepath.Join(tmp, "src"))
	if err != nil {
		f.log("%s is not a gzipped tar archive (%v), keeping the current files", archive, err)
		return "", cleanup, false
	}
	if top == "" || !isDir(filepath.Join(top, "router")) {
		f.log("%s has no router/, keeping the current files", archive)
		return "", cleanup, false
	}
	return top, cleanup, true
}

func extract(r io.Reader, dir string) (string, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return "", err
	}
	tr := tar.NewReader(zr)
	top := ""
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." || name == "pax_global_header" {
			continue
		}
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return "", fmt.Errorf("%s leaves the archive", h.Name)
		}
		dest := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return "", err
			}
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return "", err
			}
			_, err = io.Copy(out, tr)
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return "", err
			}
		default:
			continue
		}
		if top == "" {
			top = filepath.Join(dir, strings.SplitN(name, "/", 2)[0])
		}
	}
	if top != "" && !isDir(top) {
		return "", nil
	}
	return top, nil
}

func (r *run) put(src, dst string, mode os.FileMode, owner string) {
	if !exists(src) {
		return
	}
	target := r.path(dst)
	if same(src, target) {
		return
	}
	data, err := os.ReadFile(src)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(target), 0o755)
	}
	if err == nil {
		err = os.WriteFile(target+".new", data, 0o600)
	}
	if err == nil {
		err = r.Chown(target+".new", owner)
	}
	if err == nil {
		err = os.Chmod(target+".new", mode)
	}
	if err == nil {
		err = os.Rename(target+".new", target)
	}
	if err != nil {
		os.Remove(target + ".new")
		r.log("could not install %s", dst)
		r.rc = 1
		return
	}
	r.changed = append(r.changed, dst)
}

func (r *run) devices(src string) {
	os.MkdirAll(r.path("/etc/provision"), 0o755)
	want := map[string]bool{}
	for _, ext := range []string{".cms", ".toml"} {
		files, _ := filepath.Glob(filepath.Join(src, "devices", "*"+ext))
		sort.Strings(files)
		for _, file := range files {
			if !exists(file) {
				continue
			}
			base := filepath.Base(file)
			if !deviceName.MatchString(strings.TrimSuffix(base, ext)) {
				r.log("skipping %s, not a device name", base)
				continue
			}
			want[base] = true
			r.put(file, "/etc/provision/"+base, 0o640, "root:www-data")
		}
	}
	for _, ext := range []string{".cms", ".toml"} {
		files, _ := filepath.Glob(r.path("/etc/provision/*" + ext))
		sort.Strings(files)
		for _, file := range files {
			base := filepath.Base(file)
			if want[base] || !exists(file) {
				continue
			}
			if os.Remove(file) == nil {
				r.changed = append(r.changed, "/etc/provision/"+base)
			}
		}
	}
}

func (r *run) did(prefix string) bool {
	for _, c := range r.changed {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (r *run) service(name string, actions ...string) {
	for _, a := range actions {
		r.Exec(r.path("/etc/init.d/"+name), a)
	}
}

func (r *run) enabled(name string) bool {
	init := r.path("/etc/init.d/" + name)
	return exists(init) && r.Exec(init, "enabled") == nil
}

func (r *run) restart(server string) {
	if server == "provisioner" {
		takeOver := r.enabled("lighttpd")
		if takeOver {
			r.service("lighttpd", "disable", "stop")
		}
		if (takeOver || r.did("/etc/init.d/provisioner")) && exists(r.path("/etc/init.d/provisioner")) {
			r.service("provisioner", "enable", "restart")
		}
	} else {
		takeOver := r.enabled("provisioner")
		if takeOver {
			r.service("provisioner", "disable", "stop")
		}
		if (takeOver || r.did("/etc/lighttpd/")) && exists(r.path("/etc/init.d/lighttpd")) {
			r.service("lighttpd", "enable", "restart")
		}
	}
	if r.did("/etc/umdns/") {
		r.service("umdns", "restart")
	}
}

func exists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func same(a, b string) bool {
	x, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	y, err := os.ReadFile(b)
	return err == nil && bytes.Equal(x, y)
}
