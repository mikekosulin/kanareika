package onboard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mikekosulin/kanareika/internal/config"
)

// Ungrouped: the group of hosts added without one.
const Ungrouped = "ungrouped"

// node helpers on a YAML mapping
func get(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: v} }

func set(m *yaml.Node, key string, v *yaml.Node) {
	if old := get(m, key); old != nil {
		*old = *v
		return
	}
	m.Content = append(m.Content, scalar(key), v)
}

func mapping() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode} }

// freeJump: the name for a jump host at addr as user under jumps: base when that entry is this same jump (or there
// is none), else base-2, base-3, … (an entry with the same name may be another machine: never reuse it blindly).
func freeJump(jumps *yaml.Node, base, addr, user string) string {
	for i := 1; ; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		j := get(jumps, name)
		if j == nil {
			return name
		}
		a, u := get(j, "address"), get(j, "user")
		if a != nil && a.Value == addr && (u == nil && user == "" || u != nil && u.Value == user) {
			return name
		}
	}
}

// Add puts the hosts of r into an existing org file (group: the line's, else ungrouped; environment: the line's,
// else r.Env, else the org's only one, else production), with their jump hosts. Comments and key order stay. The
// result is checked by the loader before the file is replaced; the old file is kept as <file>.bak. Hosts already in
// the org are refused, not overwritten. Returns the names added.
func Add(p config.Paths, orgID string, r Request) ([]string, []string, error) {
	added, _, errs, err := AddWithSkipped(p, orgID, r)
	return added, errs, err
}

// AddWithSkipped: Add, and the host lines it skipped (unusable lines, hosts already in the org).
func AddWithSkipped(p config.Paths, orgID string, r Request) ([]string, []string, []string, error) {
	if errs := r.controlChars(); len(errs) > 0 {
		return nil, nil, errs, nil
	}
	hosts, skipped := ParseHosts(r.Hosts)
	path := filepath.Join(p.Orgs, orgID+".yml")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := config.NewLoader(p)
	if err != nil {
		return nil, nil, nil, err
	}
	org, lerrs := l.LoadOrg(path)
	if len(lerrs) > 0 {
		return nil, nil, append([]string{"the org file has problems already; fix them first:"}, lerrs...), nil
	}
	known := map[string]bool{}
	envs := map[string]bool{}
	for _, h := range org.Hosts {
		known[h.Name] = true
		envs[h.Env] = true
	}
	kept := hosts[:0:0]
	for _, h := range hosts {
		if known[h.Name] {
			skipped = append(skipped, fmt.Sprintf("host %q is in %s already, skipped", h.Name, orgID))
			continue
		}
		kept = append(kept, h)
	}
	hosts = kept
	if len(hosts) == 0 {
		return nil, nil, append([]string{"no new hosts to add"}, skipped...), nil
	}
	env := r.Env
	if env == "" && len(envs) == 1 {
		for e := range envs {
			env = e
		}
	}
	if env == "" {
		env = "production"
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, nil, nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, nil, errors.New(path + ": not a mapping")
	}
	root := doc.Content[0]
	groups := get(root, "groups")
	if groups == nil {
		groups = mapping()
		set(root, "groups", groups)
	}
	access := get(root, "access")
	if access == nil {
		access = mapping()
		set(root, "access", access)
	}
	defUser := ""
	if u := get(access, "user"); u != nil {
		defUser = u.Value
	}
	// jump hosts named by the new hosts
	jumps := get(access, "jumps")
	byName := map[string]Host{}
	for _, h := range hosts {
		byName[h.Name] = h
	}
	jumpName := map[string]string{}
	for _, h := range hosts {
		if h.Jump == "" || jumpName[h.Jump] != "" {
			continue
		}
		addr, user, name := h.Jump, "", slug(hostOnly(h.Jump))
		if j, ok := byName[strings.ToLower(h.Jump)]; ok {
			addr, user, name = j.Address, j.User, j.Name
		} else if u, a, ok := strings.Cut(h.Jump, "@"); ok {
			user, addr = u, a
		}
		if jumps == nil {
			jumps = mapping()
			set(access, "jumps", jumps)
		}
		name = freeJump(jumps, name, addr, user)
		jumpName[h.Jump] = name
		if get(jumps, name) == nil {
			j := mapping()
			set(j, "address", scalar(addr))
			if user != "" {
				set(j, "user", scalar(user))
			}
			set(jumps, name, j)
		}
	}
	var added []string
	for _, h := range hosts {
		gname, genv := h.Group, h.Env
		if gname == "" {
			gname = Ungrouped
		}
		if genv == "" {
			genv = env
		}
		g := get(groups, gname)
		if g != nil {
			if e := get(g, "env"); e != nil && e.Value != genv { // the same group in another environment
				gname += "-" + genv
				g = get(groups, gname)
			}
		}
		if g == nil {
			g = mapping()
			role, exposure := "internal", "3"
			if r.Internet && len(r.Front) == 0 || slices.Contains(r.Front, h.Group) {
				role, exposure = "front", "1"
			}
			set(g, "role", scalar(role))
			set(g, "env", scalar(genv))
			ex := scalar(exposure)
			ex.Tag = "!!int"
			set(g, "exposure", ex)
			set(g, "hosts", mapping())
			set(groups, gname, g)
		}
		hs := get(g, "hosts")
		if hs == nil {
			hs = mapping()
			set(g, "hosts", hs)
		}
		hn := mapping()
		set(hn, "address", scalar(h.Address))
		if h.User != "" && h.User != defUser {
			set(hn, "user", scalar(h.User))
		}
		if h.Jump != "" {
			set(hn, "jump", scalar(jumpName[h.Jump]))
		}
		set(hs, h.Name, hn)
		added = append(added, h.Name)
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, nil, nil, err
	}
	// the loader judges the new file where it will live: a scratch copy of the layout
	tmp, err := os.MkdirTemp("", "kanareika-add-")
	if err != nil {
		return nil, nil, nil, err
	}
	defer os.RemoveAll(tmp)
	tp := config.PathsAt(tmp)
	tp.Policy, tp.Secrets = p.Policy, p.Secrets
	if err := os.MkdirAll(tp.Orgs, 0o700); err != nil {
		return nil, nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(tp.Orgs, orgID+".yml"), out.Bytes(), 0o600); err != nil {
		return nil, nil, nil, err
	}
	tl, err := config.NewLoader(tp)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, lerrs := tl.LoadOrg(filepath.Join(tp.Orgs, orgID+".yml")); len(lerrs) > 0 {
		return nil, nil, lerrs, nil
	}
	if err := os.WriteFile(path+".bak", b, 0o600); err != nil {
		return nil, nil, nil, err
	}
	tmpFile := path + ".tmp"
	if err := os.WriteFile(tmpFile, out.Bytes(), 0o600); err != nil {
		return nil, nil, nil, err
	}
	return added, skipped, nil, os.Rename(tmpFile, path)
}
