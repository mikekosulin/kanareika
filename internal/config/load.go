package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"gopkg.in/yaml.v3"

	"github.com/mikekosulin/kanareika/assets"
)

// Loader holds the schema and the check profiles; Load reads every org file.
type Loader struct {
	Paths    Paths
	schema   *jsonschema.Schema
	raw      map[string]any // the schema document, for the role enum
	profiles map[string]any
}

const schemaID = "urn:kanareika:org.schema.json"

// defaultsFS: the built-in policy and schema files; tests replace it.
var defaultsFS = assets.Defaults

func NewLoader(p Paths) (*Loader, error) {
	raw, err := readJSON(p, "schemas/org.schema.json")
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	// an absolute id of its own: a relative one resolves against the working directory, which then shows in errors
	_ = c.AddResource(schemaID, raw) // a fresh compiler and a constant absolute id: it cannot fail
	sch, err := c.Compile(schemaID)
	if err != nil {
		return nil, fmt.Errorf("schemas/org.schema.json: %w", err)
	}
	l := &Loader{Paths: p, schema: sch, raw: raw.(map[string]any)}
	if l.profiles, err = l.loadProfiles(); err != nil {
		return nil, err
	}
	return l, nil
}

// Policy reads policy/<name> from the working directory if present, else the built-in default.
func Policy(p Paths, name string) ([]byte, error) {
	if b, err := os.ReadFile(filepath.Join(p.Policy, name)); err == nil {
		return b, nil
	}
	return fs.ReadFile(defaultsFS(), "policy/"+name)
}

// readJSON: a built-in file (the org schema belongs to the binary that implements it).
func readJSON(_ Paths, rel string) (any, error) {
	b, err := fs.ReadFile(defaultsFS(), rel)
	if err != nil {
		return nil, err
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(b))
}

// YAML decodes into JSON-compatible data: dates become YYYY-MM-DD strings, numbers float64 (as JSON would).
func YAML(b []byte) (any, error) {
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return normalize(v), nil
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalize(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = normalize(x)
		}
		return t
	case time.Time:
		if t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 {
			return t.Format("2006-01-02")
		}
		return t.Format(time.RFC3339)
	case int:
		return float64(t)
	}
	return v
}

func (l *Loader) loadProfiles() (map[string]any, error) {
	b, err := Policy(l.Paths, "profiles.yml")
	if err != nil {
		return nil, err
	}
	data, err := YAML(b)
	if err != nil {
		return nil, fmt.Errorf("policy/profiles.yml: %w", err)
	}
	// validate against the checks definition of the org schema
	sub := map[string]any{
		"$defs": l.raw["$defs"], "type": "object", "additionalProperties": false,
		"properties": map[string]any{
			"default": map[string]any{"$ref": "#/$defs/checks"},
			"roles":   map[string]any{"type": "object", "additionalProperties": map[string]any{"$ref": "#/$defs/checks"}},
		},
	}
	c := jsonschema.NewCompiler()
	_ = c.AddResource("urn:kanareika:profiles.json", sub)
	sch, err := c.Compile("urn:kanareika:profiles.json")
	if err != nil {
		return nil, err
	}
	if err := sch.Validate(data); err != nil {
		return nil, fmt.Errorf("policy/profiles.yml: %s", strings.Join(schemaErrors(err), "; "))
	}
	return mapOf(data), nil
}

// schemaErrors: one line per failed check, "where: what" (<root> for the document), deepest causes only (the
// "validation failed" of their parents says nothing).
func schemaErrors(err error) []string {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []string{err.Error()}
	}
	p := message.NewPrinter(language.English)
	var out []string
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, c := range e.Causes {
				walk(c)
			}
			return
		}
		loc := strings.Join(e.InstanceLocation, "/")
		if loc == "" {
			loc = "<root>"
		}
		if line := loc + ": " + e.ErrorKind.LocalizedString(p); !slices.Contains(out, line) {
			out = append(out, line)
		}
	}
	walk(ve)
	return out
}

// OrgFiles: orgs/*.yml except _template / _example.
func (l *Loader) OrgFiles() []string {
	m, _ := filepath.Glob(filepath.Join(l.Paths.Orgs, "*.yml"))
	var out []string
	for _, p := range m {
		if !strings.HasPrefix(filepath.Base(p), "_") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// LoadAll loads every org; errors are collected, a broken file does not stop the others.
func (l *Loader) LoadAll() ([]*Org, []string) {
	var orgs []*Org
	var errs []string
	ids := map[string]bool{}
	for _, p := range l.OrgFiles() {
		o, e := l.LoadOrg(p)
		errs = append(errs, e...)
		if o == nil {
			continue
		}
		if ids[o.ID] {
			errs = append(errs, fmt.Sprintf("%s: duplicate org id %s", filepath.Base(p), o.ID))
		}
		ids[o.ID] = true
		orgs = append(orgs, o)
	}
	return orgs, append(errs, CrossOrgConflicts(orgs)...)
}

// LoadOrg returns (org, errors); org is nil when the file is unusable.
func (l *Loader) LoadOrg(path string) (*Org, []string) {
	file := filepath.Base(path)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", file, err)}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, []string{fmt.Sprintf("%s: YAML error: %v", file, err)}
	}
	migrated, err := Migrate(&doc) // older formats are upgraded in memory, the file stays as is
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", file, err)}
	}
	var raw any
	if err := doc.Decode(&raw); err != nil {
		return nil, []string{fmt.Sprintf("%s: YAML error: %v", file, err)}
	}
	v := normalize(raw)
	if v == nil {
		v = map[string]any{}
	}
	if err := l.schema.Validate(v); err != nil {
		var out []string
		for _, e := range schemaErrors(err) {
			out = append(out, file+": "+e)
		}
		return nil, out
	}
	data := v.(map[string]any)
	var errs []string
	errf := func(format string, a ...any) { errs = append(errs, file+": "+fmt.Sprintf(format, a...)) }

	orgID := str(mapOf(data["org"]), "id")
	if name := strings.TrimSuffix(file, ".yml"); orgID != name {
		errf("org.id '%s' must match file name '%s'", orgID, name)
	}
	access := mapOf(data["access"])
	jumps := mapOf(access["jumps"])
	for _, jname := range keys(jumps) {
		if j := str(mapOf(jumps[jname]), "jump"); j != "" && jumps[j] == nil {
			errf("jump '%s' refers to unknown jump '%s'", jname, j)
		}
	}
	for _, jname := range keys(jumps) {
		j := mapOf(jumps[jname])
		if _, err := portOf(j); err != nil {
			errf("jump '%s': %v", jname, err)
		}
	}
	for _, jname := range keys(jumps) { // cycles
		seen := map[string]bool{}
		for cur := jname; cur != ""; cur = str(mapOf(jumps[cur]), "jump") {
			if seen[cur] {
				errf("jump chain cycle at '%s'", jname)
				break
			}
			seen[cur] = true
		}
	}

	orgChecks := mapOf(data["checks"])
	defaults := mapOf(l.profiles["default"])
	org := &Org{ID: orgID, Path: path, Data: data, Checks: MergeChecks(defaults, orgChecks), Migrated: migrated, paths: l.Paths}
	roles := enum(mapOf(mapOf(l.raw["$defs"])["role"]))
	hostChecks := map[string]any{}
	for k, v := range orgChecks {
		if contains(HostModules, k) {
			hostChecks[k] = v
		}
	}

	seenHosts := map[string]string{}
	groups := mapOf(data["groups"])
	for _, gname := range ordered(&doc, groups, "groups") {
		group := mapOf(groups[gname])
		role := str(group, "role")
		if role == "" {
			role = gname
		}
		if !contains(roles, role) {
			errf("group '%s' has no valid role (set role: explicitly)", gname)
			continue
		}
		for _, m := range OrgModules {
			if _, ok := mapOf(group["checks"])[m]; ok {
				errf("group '%s': '%s' can only be set in top-level checks", gname, m)
			}
		}
		hosts := mapOf(group["hosts"])
		for _, hname := range ordered(&doc, hosts, "groups", gname, "hosts") {
			h := mapOf(hosts[hname])
			if g, ok := seenHosts[hname]; ok {
				errf("host '%s' defined in groups '%s' and '%s'", hname, g, gname)
				continue
			}
			seenHosts[hname] = gname
			for _, m := range OrgModules {
				if _, ok := mapOf(h["checks"])[m]; ok {
					errf("host '%s': '%s' can only be set in top-level checks", hname, m)
				}
			}
			jump := str(group, "jump")
			if v, ok := h["jump"].(string); ok {
				jump = v
			}
			if jump != "" && jumps[jump] == nil {
				errf("host '%s' uses unknown jump '%s'", hname, jump)
			}
			checks := MergeChecks(defaults, mapOf(mapOf(l.profiles["roles"])[role]), hostChecks,
				mapOf(group["checks"]), mapOf(h["checks"]))
			for _, m := range OrgModules {
				delete(checks, m)
			}
			env := str(group, "env")
			if env == "" {
				env = DefaultEnv
			}
			user := str(h, "user")
			if user == "" {
				user = str(access, "user")
			}
			sudo, _ := access["sudo"].(bool)
			if v, ok := h["sudo"].(bool); ok {
				sudo = v
			}
			admin := str(h, "admin_user")
			if admin == "" {
				admin = str(access, "admin_user")
			}
			legacy, _ := h["legacy_ssh"].(bool)
			addr, _, _ := SplitAddress(str(h, "address")) // a malformed address is reported by portOf
			port, err := portOf(h)
			if err != nil {
				errf("host '%s': %v", hname, err)
			}
			if port == 0 {
				port = intOr(group, "port", intOr(access, "port", DefaultPort))
			}
			org.Hosts = append(org.Hosts, Host{
				Org: orgID, Env: env, Name: hname, Group: gname, Role: role,
				Address: addr, Port: port, User: user,
				Exposure: intOr(h, "exposure", intOr(group, "exposure", 3)),
				Jump:     jump, Sudo: sudo, OSHint: str(h, "os"), Checks: checks,
				Privilege: privilege(h, access), AdminUser: admin, LegacySSH: legacy,
			})
		}
	}

	names := map[string]bool{}
	for _, h := range org.Hosts {
		names[h.Name] = true
	}
	for _, ex := range org.Exceptions() {
		for _, hn := range strings_(ex["hosts"]) {
			if !names[hn] {
				errf("exception %s refers to unknown host '%s'", str(ex, "id"), hn)
			}
		}
	}

	envs := org.Envs()
	if len(envs) > 1 && contains(envs, DefaultEnv) {
		errf("some groups have env and some don't; set env on every group")
	}
	var extEnvs []string
	switch ext := data["external"].(type) {
	case map[string]any:
		extEnvs = keys(ext)
	case []any:
		if len(ext) > 0 {
			extEnvs = []string{DefaultEnv}
		}
	}
	for _, e := range extEnvs {
		if !contains(envs, e) {
			hint := "known: " + strings.Join(envs, ", ")
			if e == DefaultEnv {
				hint = "use external: <env>: [...]"
			}
			errf("external: env '%s' has no hosts (%s)", e, hint)
		}
	}
	for _, c := range list(data["k8s"]) {
		cl := mapOf(c)
		e := str(cl, "env")
		if e == "" {
			e = DefaultEnv
		}
		if !contains(envs, e) {
			errf("k8s %s: env '%s' has no hosts", str(cl, "name"), e)
		}
	}

	c := org.Consent()
	if str(c, "valid_until") < str(c, "signed") {
		errf("consent.valid_until is before consent.signed")
	}
	if tz := str(mapOf(c["window"]), "tz"); tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			errf("unknown timezone '%s'", tz)
		}
	}
	return org, errs
}

func privilege(h, access map[string]any) string {
	mode := str(h, "privilege")
	if mode == "" {
		mode = str(access, "privilege")
	}
	if mode == "" { // legacy `sudo: true|false`
		sudo, _ := access["sudo"].(bool)
		if v, ok := h["sudo"].(bool); ok {
			sudo = v
		}
		mode = "none"
		if sudo {
			mode = "sudo"
		}
	}
	user := str(h, "user")
	if user == "" {
		user = str(access, "user")
	}
	if mode == "sudo" && user == "root" {
		mode = "none" // already root: no sudo needed (and it may not be installed)
	}
	return mode
}

// --- checks merging ---------------------------------------------------------------------------------------------

func norm(v any) map[string]any {
	if b, ok := v.(bool); ok {
		return map[string]any{"enabled": b}
	}
	out := deepCopy(mapOf(v))
	if _, ok := out["enabled"]; !ok {
		out["enabled"] = true
	}
	return out
}

// DeepMerge: maps merge recursively; scalars and lists from over replace.
func DeepMerge(base, over map[string]any) map[string]any {
	out := deepCopy(base)
	for k, v := range over {
		if vm, ok := v.(map[string]any); ok {
			if bm, ok := out[k].(map[string]any); ok {
				out[k] = DeepMerge(bm, vm)
				continue
			}
		}
		out[k] = deepCopyAny(v)
	}
	return out
}

// MergeChecks applies layers in order: default -> role -> org -> group -> host.
func MergeChecks(layers ...map[string]any) Checks {
	out := Checks{}
	for _, layer := range layers {
		for _, mod := range keys(layer) {
			val := layer[mod]
			if vm, ok := val.(map[string]any); ok {
				if _, has := vm["enabled"]; !has {
					if prev, ok := out[mod]; ok { // partial override keeps the previous enabled state
						out[mod] = DeepMerge(prev, vm)
						continue
					}
				}
			}
			out[mod] = DeepMerge(out[mod], norm(val))
		}
	}
	for _, m := range Modules {
		if _, ok := out[m]; !ok {
			out[m] = map[string]any{"enabled": false}
		}
	}
	return out
}

func deepCopy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyAny(v)
	}
	return out
}

func deepCopyAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return deepCopy(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopyAny(x)
		}
		return out
	}
	return v
}

// --- cross-org isolation ----------------------------------------------------------------------------------------

type target struct {
	label  string
	prefix netip.Prefix
	name   string // hostname when not an address
}

func targetKey(label, value string) target {
	v := strings.TrimSpace(value)
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			v = u.Hostname()
		}
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		return target{label: label, prefix: p.Masked()}
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return target{label: label, prefix: netip.PrefixFrom(a, a.BitLen())}
	}
	return target{label: label, name: strings.TrimSuffix(strings.ToLower(v), ".")}
}

func (a target) overlaps(b target) bool {
	if a.name != "" || b.name != "" {
		return a.name == b.name
	}
	return a.prefix.Overlaps(b.prefix)
}

// portOf: the port a host or jump entry sets explicitly (its "port", else one inside its address), 0 for none;
// an error when the address is malformed or both are set and disagree.
func portOf(m map[string]any) (int, error) {
	_, inAddr, err := SplitAddress(str(m, "address"))
	if err != nil {
		return 0, err
	}
	explicit := intOr(m, "port", 0)
	if explicit != 0 && inAddr != 0 && explicit != inAddr {
		return 0, fmt.Errorf("port %d and address %q disagree", explicit, str(m, "address"))
	}
	if explicit != 0 {
		return explicit, nil
	}
	return inAddr, nil
}

func orgTargets(o *Org) []target {
	var out []target
	for _, h := range o.Hosts {
		out = append(out, targetKey("host "+h.Name, h.Address))
	}
	jumps := o.Jumps()
	for _, n := range keys(toAny(jumps)) {
		out = append(out, targetKey("jump "+n, str(jumps[n], "address")))
	}
	for _, env := range o.Envs() {
		for _, e := range o.External(env) {
			out = append(out, targetKey("external "+e, e))
		}
	}
	return out
}

// CrossOrgConflicts: the same address must never belong to two organizations.
func CrossOrgConflicts(orgs []*Org) []string {
	type item struct {
		org string
		t   target
	}
	var all []item
	for _, o := range orgs {
		for _, t := range orgTargets(o) {
			all = append(all, item{o.ID, t})
		}
	}
	var errs []string
	for i, a := range all {
		for _, b := range all[i+1:] {
			if a.org != b.org && a.t.overlaps(b.t) {
				errs = append(errs, fmt.Sprintf("address overlap between orgs: %s/%s and %s/%s", a.org, a.t.label, b.org, b.t.label))
			}
		}
	}
	return errs
}

// --- helpers ----------------------------------------------------------------------------------------------------

// ordered: keys of the mapping at path in file order (Go maps have none); hosts are listed and scanned in the
// order they are written. Falls back to sorted keys.
func ordered(doc *yaml.Node, m map[string]any, path ...string) []string {
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	for _, k := range path {
		var next *yaml.Node
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == k {
					next = n.Content[i+1]
				}
			}
		}
		if next == nil {
			return keys(m)
		}
		n = next
	}
	var out []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		if _, ok := m[n.Content[i].Value]; ok {
			out = append(out, n.Content[i].Value)
		}
	}
	if len(out) != len(m) {
		return keys(m)
	}
	return out
}

// keys sorted, for determinism where file order does not matter.
func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toAny[V any](m map[string]V) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func enum(m map[string]any) []string { return strings_(m["enum"]) }

// MarshalChecks is a stable JSON rendering for comparisons in tests.
func MarshalChecks(c Checks) string { b, _ := json.Marshal(c); return string(b) }
