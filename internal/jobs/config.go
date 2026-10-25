package jobs

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/bbusse/provisioner/internal/store"
)

type ConfigOptions struct {
	Name     string   `json:"-"`
	User     string   `json:"user,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Timezone string   `json:"timezone,omitempty"`
	SSHKeys  []string `json:"ssh_keys,omitempty"`
	K8s      string   `json:"k8s,omitempty"`
	NoWG     bool     `json:"no_wg,omitempty"`
}

var (
	reUser     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reRole     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	reTimezone = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`)
	reSSHKey   = regexp.MustCompile(`^(ssh-|ecdsa-|sk-)[A-Za-z0-9@.-]+ [A-Za-z0-9+/]+=*( [^\x00-\x1f\x7f]*)?$`)
)

func (j *Jobs) Config(o ConfigOptions) error {
	name := o.Name
	if err := checkDevice(name); err != nil {
		return err
	}
	signer, err := j.Store.Signer()
	if err != nil {
		return err
	}
	plainPath := j.Store.PlainPath(name)
	if _, err := os.Stat(plainPath); err == nil {
		return fmt.Errorf("%s exists, edit it and run device %s", plainPath, name)
	}
	if o.User != "" && !reUser.MatchString(o.User) {
		return fmt.Errorf("not a user name: %s", o.User)
	}
	for _, role := range o.Roles {
		if !reRole.MatchString(role) {
			return fmt.Errorf("not a role name: %s", role)
		}
	}
	if o.Timezone != "" && !reTimezone.MatchString(o.Timezone) {
		return fmt.Errorf("not a time zone like Europe/Berlin: %s", o.Timezone)
	}
	for _, key := range o.SSHKeys {
		if !reSSHKey.MatchString(key) {
			return fmt.Errorf("not an ssh public key: %s", key)
		}
	}
	var cluster, role string
	if o.K8s != "" {
		var ok bool
		cluster, role, ok = strings.Cut(o.K8s, ":")
		if err := store.CheckName(cluster); err != nil {
			return err
		}
		if !ok || (role != "master" && role != "client") {
			return fmt.Errorf("--k8s takes CLUSTER:master or CLUSTER:client")
		}
		if !store.Exists(j.S.CertsDir + "/k8s-" + cluster + "/k8s.toml") {
			return fmt.Errorf("no cluster %s in %s/k8s-%s, run cluster %s", cluster, j.S.CertsDir, cluster, cluster)
		}
	}

	if err := j.deviceCert(name); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[system]\nhostname = %s\n", tomlString(name))
	if o.User != "" {
		fmt.Fprintf(&b, "user = %s\n", tomlString(o.User))
	}
	if len(o.Roles) > 0 {
		fmt.Fprintf(&b, "roles = %s\n", tomlList(o.Roles))
	}
	if o.Timezone != "" {
		fmt.Fprintf(&b, "timezone = %s\n", tomlString(o.Timezone))
	}
	if len(o.SSHKeys) > 0 {
		b.WriteString("\n[ssh]\nauthorized_keys = [\n")
		for _, key := range o.SSHKeys {
			fmt.Fprintf(&b, "    %s,\n", tomlString(key))
		}
		b.WriteString("]\n")
	}
	if err := store.PrivateDir(j.Store.Plain); err != nil {
		return err
	}
	if err := store.WriteFile(plainPath, []byte(b.String()), 0o600); err != nil {
		return err
	}
	j.Log("wrote %s", plainPath)

	if !o.NoWG {
		if err := j.wgPeer(name, plainPath); err != nil {
			return err
		}
	}
	if err := j.Store.CheckTOML(plainPath); err != nil {
		return err
	}
	if cluster != "" {
		err = j.k8sJoin(name, cluster, role, signer)
	} else {
		err = j.Store.Seal(name, signer, j.Log)
	}
	if err != nil {
		return err
	}
	j.deviceDone(name)
	return nil
}
