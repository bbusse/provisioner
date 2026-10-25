package jobs

import (
	"fmt"
	"regexp"
	"strings"
)

func tomlString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func tomlList(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = tomlString(item)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
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

var (
	reRolesLine = regexp.MustCompile(`^\s*roles\s*=`)
	reRolesList = regexp.MustCompile(`^\s*roles\s*=\s*\[(.*)\]\s*$`)
	reQuoted    = regexp.MustCompile(`"([^"]*)"`)
)

func addRole(text, role string) (string, error) {
	lines := strings.Split(text, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "[system]" {
			start = i
			break
		}
	}
	if start < 0 {
		head := []string{"[system]", fmt.Sprintf(`roles = ["%s"]`, role), ""}
		return strings.Join(append(head, lines...), "\n"), nil
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "[") {
			end = i
			break
		}
	}
	found := -1
	for i := start + 1; i < end; i++ {
		if reRolesLine.MatchString(lines[i]) {
			found = i
			break
		}
	}
	if found < 0 {
		last := start
		for i := start; i < end; i++ {
			if strings.TrimSpace(lines[i]) != "" {
				last = i
			}
		}
		lines = append(lines[:last+1], append([]string{fmt.Sprintf(`roles = ["%s"]`, role)}, lines[last+1:]...)...)
		return strings.Join(lines, "\n"), nil
	}
	m := reRolesList.FindStringSubmatch(lines[found])
	if m == nil {
		return "", fmt.Errorf("roles is not a one-line list, add %s by hand", role)
	}
	var roles []string
	for _, q := range reQuoted.FindAllStringSubmatch(m[1], -1) {
		roles = append(roles, q[1])
	}
	has := false
	for _, r := range roles {
		if r == role {
			has = true
		}
	}
	if !has {
		roles = append(roles, role)
	}
	quoted := make([]string, len(roles))
	for i, r := range roles {
		quoted[i] = `"` + r + `"`
	}
	lines[found] = "roles = [" + strings.Join(quoted, ", ") + "]"
	return strings.Join(lines, "\n"), nil
}

func hasSection(text string, re *regexp.Regexp) bool {
	for _, l := range strings.Split(text, "\n") {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

var (
	reWGSection  = regexp.MustCompile(`^\[wg\]`)
	reK8sSection = regexp.MustCompile(`^\[k8s(\]|\.)`)
)

func isK8sMaster(text, cluster string) bool {
	section := ""
	member, pki := false, false
	want := fmt.Sprintf(`cluster = "%s"`, cluster)
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "[") {
			section = l
		}
		if section == "[k8s]" && l == want {
			member = true
		}
		if l == "[k8s.pki]" {
			pki = true
		}
	}
	return member && pki
}
