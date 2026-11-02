// Package config loads, validates and resolves orgs/<id>.yml: hosts, jump chains, checks per host, consent.
// The file format is the one described in docs/org-file.md and schemas/org.schema.json.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

var (
	HostModules = []string{"os_packages", "software_fs", "docker", "swarm", "mongo", "hardening", "health", "access",
		"exposure", "network_internal"}
	OrgModules = []string{"k8s", "network_external"}
	Modules    = append(slices.Clone(HostModules), OrgModules...)
)

const DefaultEnv = "default"

// Paths of the working directory: orgs/, policy/ (optional overrides), secrets/, reports/.
type Paths struct {
	Home    string
	Orgs    string
	Policy  string
	Secrets string
	Reports string
}

// NewPaths: KANAREIKA_HOME or the current directory.
func NewPaths() Paths {
	home := os.Getenv("KANAREIKA_HOME")
	if home == "" {
		home, _ = os.Getwd()
	}
	return PathsAt(home)
}

func PathsAt(home string) Paths {
	return Paths{Home: home, Orgs: filepath.Join(home, "orgs"), Policy: filepath.Join(home, "policy"),
		Secrets: filepath.Join(home, "secrets"), Reports: filepath.Join(home, "reports")}
}

// Checks: module -> settings; every module has "enabled".
type Checks map[string]map[string]any

func (c Checks) Enabled(module string) bool {
	v, _ := c[module]["enabled"].(bool)
	return v
}

type Host struct {
	Org       string `json:"org"`
	Env       string `json:"env"`
	Name      string `json:"name"`
	Group     string `json:"group"`
	Role      string `json:"role"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	User      string `json:"user"`
	Exposure  int    `json:"exposure"`
	Jump      string `json:"jump"`
	Sudo      bool   `json:"sudo"`
	OSHint    string `json:"os_hint"`
	Checks    Checks `json:"checks"`
	Privilege string `json:"privilege"`  // none | sudo | helper, see package priv
	AdminUser string `json:"admin_user"` // who applies fixes; the audit user only reads
	LegacySSH bool   `json:"legacy_ssh"` // allow ssh-rsa (SHA-1) for this host only
}

func (h Host) Enabled(module string) bool { return h.Checks.Enabled(module) }

type Org struct {
	ID     string
	Path   string
	Data   map[string]any // the file as loaded (dates as YYYY-MM-DD strings)
	Hosts  []Host
	Checks Checks // org-level modules (k8s, network_external)
	// Migrated: format upgrades applied in memory on load (the file is older); `kanareika migrate` writes them
	Migrated []string
	paths    Paths
}

func (o *Org) Consent() map[string]any { return mapOf(o.Data["consent"]) }
func (o *Org) Access() map[string]any  { return mapOf(o.Data["access"]) }
func (o *Org) Name() string            { s, _ := mapOf(o.Data["org"])["name"].(string); return s }
func (o *Org) Enabled(m string) bool   { return o.Checks.Enabled(m) }

// Jumps: name -> {address, port, user, jump}.
func (o *Org) Jumps() map[string]map[string]any {
	out := map[string]map[string]any{}
	for k, v := range mapOf(o.Access()["jumps"]) {
		out[k] = mapOf(v)
	}
	return out
}

func (o *Org) Envs() []string {
	set := map[string]bool{}
	for _, h := range o.Hosts {
		set[h.Env] = true
	}
	out := make([]string, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// External targets of one environment.
func (o *Org) External(env string) []string {
	switch ext := o.Data["external"].(type) {
	case map[string]any:
		return strings_(ext[env])
	case []any:
		if env == DefaultEnv {
			return strings_(ext)
		}
	}
	return nil
}

// K8s clusters of one environment.
func (o *Org) K8s(env string) []map[string]any {
	var out []map[string]any
	for _, c := range list(o.Data["k8s"]) {
		m := mapOf(c)
		e, _ := m["env"].(string)
		if e == "" {
			e = DefaultEnv
		}
		if e == env {
			out = append(out, m)
		}
	}
	return out
}

// Exceptions: accepted risks as written in the file.
func (o *Org) Exceptions() []map[string]any {
	var out []map[string]any
	for _, e := range list(o.Data["exceptions"]) {
		out = append(out, mapOf(e))
	}
	return out
}

// Secret resolves a path inside secrets/; "" when rel is empty.
func (o *Org) Secret(rel string) (string, error) {
	if rel == "" {
		return "", nil
	}
	base, _ := filepath.Abs(o.paths.Secrets)
	p, _ := filepath.Abs(filepath.Join(base, rel))
	if !strings.HasPrefix(p, base+string(filepath.Separator)) {
		return "", fmt.Errorf("%s: secret path escapes secrets/: %s", o.ID, rel)
	}
	return p, nil
}

// --- small helpers for the loosely typed YAML data -------------------------------------------------------------

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func list(v any) []any { l, _ := v.([]any); return l }

func strings_(v any) []string {
	var out []string
	for _, x := range list(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func intOr(m map[string]any, k string, def int) int {
	switch v := m[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return def
}
