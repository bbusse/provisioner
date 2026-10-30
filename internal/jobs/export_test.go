package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func untar(t *testing.T, data []byte) map[string]*tar.Header {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*tar.Header{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = h
	}
}

func TestExportLaysOutWhatFetchInstalls(t *testing.T) {
	e := setup(t)
	e.signer()
	e.must(e.j.Cluster(ClusterOptions{Name: "example"}))
	e.device("m1")
	e.device("c1")
	e.must(e.j.K8s("m1", "example", "master"))
	e.must(e.j.K8s("c1", "example", "client"))

	var m bytes.Buffer
	e.must(e.j.Export("m1", &m))
	files := untar(t, m.Bytes())
	for name, mode := range map[string]int64{"k8s.conf": 0o600, "k8s-pki/": 0o700, "k8s-pki/etcd/": 0o755,
		"k8s-pki/ca.key": 0o600, "k8s-pki/etcd/ca.crt": 0o600, "k8s-pki/sa.pub": 0o600} {
		if h, ok := files[name]; !ok || h.Mode != mode {
			t.Errorf("%s: %+v", name, h)
		}
	}
	if len(files) != 11 {
		t.Errorf("%d entries", len(files))
	}

	var c bytes.Buffer
	e.must(e.j.Export("c1", &c))
	if files := untar(t, c.Bytes()); len(files) != 1 || files["k8s.conf"] == nil {
		t.Errorf("client export %v", files)
	}
	if err := e.j.Export("nodevice", io.Discard); err == nil {
		t.Error("exported a device without a plain file")
	}
}

func TestDeployPipesTheExportToSSH(t *testing.T) {
	e := setup(t)
	e.signer()
	e.must(e.j.Cluster(ClusterOptions{Name: "example"}))
	e.device("m1")
	e.must(e.j.K8s("m1", "example", "master"))
	bin := t.TempDir()
	got := filepath.Join(bin, "got")
	os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\necho \"$@\" >"+got+".args\ncat >"+got+"\n"), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	e.must(e.j.Deploy("m1", "root@bsd-cp"))
	args, _ := os.ReadFile(got + ".args")
	if !strings.HasPrefix(string(args), "root@bsd-cp rm -rf /etc/provision/k8s-pki /etc/provision/k8s-flux && ") {
		t.Errorf("ssh %s", args)
	}
	data, _ := os.ReadFile(got)
	var want bytes.Buffer
	e.must(e.j.Export("m1", &want))
	if len(untar(t, data)) != len(untar(t, want.Bytes())) {
		t.Error("ssh got another tar than export writes")
	}
}
