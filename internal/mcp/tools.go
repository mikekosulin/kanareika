package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/prompt"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/remediate"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Instructions: what the server tells the agent on initialize.
const Instructions = "Kanareika: security audit results for our servers, by organization and environment (production/staging). " +
	"Start with list_orgs, then get_summary. list_actions — what to fix by priority (P1 urgent … P4 background); " +
	"get_host — everything about one server (packages, SSH access, ports, firewall, health, time); " +
	"search_packages — where a vulnerable package or CVE is installed; fix_prompt / fix_plan — a ready task or " +
	"rollback-capable fix steps for selected actions. Data is the latest known state of each host. " +
	"OS packages are checked against the host's own repositories: fix_state available = update now, reboot = " +
	"installed, reboot pending, vendor = no fix in the repositories yet (action cat 'vendor': mitigate or accept " +
	"until available). CVEs already fixed in the installed build (package changelog) are left out of actions. " +
	"All tools are read-only; scans are started by a human. Pass lang=ru or lang=zh for Russian or Chinese texts."

func orgEnv() pyfmt.Obj {
	return pyfmt.O(
		"lang", pyfmt.O("enum", i18n.Langs(), "description", "language of texts (default en)"),
		"org", pyfmt.O("type", "string", "description", "organization id from list_orgs"),
		"env", pyfmt.O("type", "string", "description", "environment (production, staging, ...); optional if there is only one"),
	)
}

func schema(props pyfmt.Obj, required ...string) pyfmt.Obj {
	s := pyfmt.O("type", "object", "properties", props)
	if required != nil {
		s = append(s, pyfmt.KV{K: "required", V: required})
	}
	return s
}

func tool(name, desc string, input pyfmt.Obj) pyfmt.Obj {
	return pyfmt.O("name", name, "description", desc, "inputSchema", input)
}

// Tools: names, descriptions and input schemas as tools/list returns them. Scans are deliberately not here: they
// connect to real servers, so starting one stays a human decision.
var Tools = []pyfmt.Obj{
	tool("list_orgs", "Organizations, their environments, host counts and the last full scan summary.", schema(pyfmt.Obj{})),
	tool("get_summary", "Environment summary: packages to update by priority, hosts with status, top 10 actions.",
		schema(orgEnv(), "org")),
	tool("list_actions", "To-do actions (update kernel, OS packages, image, close a port, disable password login…) with hosts, priority, due date, KEV and pre-auth RCE flags.",
		schema(append(orgEnv(),
			pyfmt.KV{K: "host", V: pyfmt.O("type", "string", "description", "only actions on this host")},
			pyfmt.KV{K: "priority", V: pyfmt.O("type", "array", "items", pyfmt.O("enum", []string{"P1", "P2", "P3", "P4"}), "description", "default P1–P3")},
			pyfmt.KV{K: "category", V: pyfmt.O("type", "array", "items", pyfmt.O("enum", prompt.Categories))},
			pyfmt.KV{K: "rce_only", V: pyfmt.O("type", "boolean", "description", "only where unauthenticated remote code execution is possible")},
			pyfmt.KV{K: "limit", V: pyfmt.O("type", "integer", "default", 50)}), "org")),
	tool("get_host", "Everything about one server: OS, packages to update, actions, SSH (passwords, root, keys, logins, attackers), public IPs and ports, firewall, disks, kernel errors, units, time/NTP.",
		schema(append(orgEnv(), pyfmt.KV{K: "host", V: pyfmt.O("type", "string")}), "org", "host")),
	tool("search_packages", "Find vulnerable packages by package name, image or CVE (substring).",
		schema(append(orgEnv(), pyfmt.KV{K: "query", V: pyfmt.O("type", "string")}, pyfmt.KV{K: "host", V: pyfmt.O("type", "string")},
			pyfmt.KV{K: "limit", V: pyfmt.O("type", "integer", "default", 50)}), "org", "query")),
	tool("fix_prompt", "A ready task to fix selected actions: hosts, how to connect (jump), what and how to fix, safety rules, re-check command, embedded fix.sh.",
		schema(append(orgEnv(), pyfmt.KV{K: "action_ids", V: pyfmt.O("type", "array", "items", pyfmt.O("type", "string"), "description", "ids from list_actions")}),
			"org", "action_ids")),
	tool("fix_plan", "Step-by-step fix plan for selected actions: per host how to connect, commands to apply (with backups), verify and roll back. Execute one step at a time and show results; nothing reboots automatically.",
		schema(append(orgEnv(), pyfmt.KV{K: "action_ids", V: pyfmt.O("type", "array", "items", pyfmt.O("type", "string"))}), "org", "action_ids")),
	tool("list_runs", "Run history of an environment: full and partial runs with priority counts.", schema(orgEnv(), "org")),
}

// args of a tools/call, as the client sent them.
type args map[string]any

func (a args) str(k string) string { s, _ := a[k].(string); return s }

func (a args) lang() string {
	if l := a.str("lang"); l != "" {
		return l
	}
	return "en"
}

// strs: a list argument; nil when absent or empty.
func (a args) strs(k string) []string {
	l, _ := a[k].([]any)
	var out []string
	for _, x := range l {
		out = append(out, pyfmt.Str(x))
	}
	return out
}

// limit: Python's int(a.get("limit") or 50), applied as a slice bound (a negative one counts from the end).
func (a args) limit(n int) (int, error) {
	l := 50
	if v, ok := a["limit"]; ok && pyfmt.Truthy(v) {
		f, ok := num(v)
		if !ok {
			return 0, fmt.Errorf("invalid limit: %s", pyfmt.Str(v))
		}
		l = int(f)
	}
	if l < 0 {
		l = max(0, n+l)
	}
	return min(l, n), nil
}

// pyArg: an argument as Python's f-string shows it ('None' when absent).
func (a args) pyArg(k string) string { return pyfmt.Str(a[k]) }

// env resolves org and env of a call; env may be left out when the org has only one.
func (s *Server) env(a args) (*config.Org, string, error) {
	s.store.Reload()
	org := s.store.Org(a.str("org"))
	if _, isStr := a["org"].(string); org == nil || !isStr {
		return nil, "", fmt.Errorf("no organization '%s'. Known: %s", a.pyArg("org"), strings.Join(s.store.OrgIDs(), ", "))
	}
	envs := org.Envs()
	env := a.str("env")
	if !pyfmt.Truthy(a["env"]) && len(envs) == 1 {
		env = envs[0]
	}
	if _, isStr := a["env"].(string); (pyfmt.Truthy(a["env"]) && !isStr) || !slices.Contains(envs, env) {
		return nil, "", fmt.Errorf("specify env: %s", strings.Join(envs, ", "))
	}
	return org, env, nil
}

func (s *Server) view(a args) (*config.Org, string, *report.View, error) {
	org, env, err := s.env(a)
	if err != nil {
		return nil, "", nil, err
	}
	v, err := s.store.Current(org.ID, env)
	return org, env, v, err
}

// action: an action as tools show it — texts in lang, empty fields left out.
func action(a *report.Action, lang string) pyfmt.Obj {
	var out pyfmt.Obj
	add := func(k string, v any) {
		if pyfmt.Truthy(v) {
			out = append(out, pyfmt.KV{K: k, V: v})
		}
	}
	add("id", a.ID)
	add("priority", ptr(a.Priority))
	add("cat", a.Cat)
	add("title", i18n.Render(a.Title, a.Msg, a.Args, lang))
	add("hosts", a.Hosts)
	add("detail", a.Detail)
	add("hint", i18n.Render(a.Hint, a.HintMsg, a.HintArgs, lang))
	add("due", ptr(a.Due))
	add("kev", a.KEV)
	if a.RCE != nil {
		add("rce", *a.RCE)
	}
	add("cves", a.CVEs)
	add("image", ptr(a.Image))
	add("path", ptr(a.Path))
	if out == nil {
		return pyfmt.Obj{}
	}
	return out
}

func (s *Server) listOrgs(args) (any, error) { return s.store.Overview(), nil }

func (s *Server) getSummary(a args) (any, error) {
	org, env, v, err := s.view(a)
	if err != nil {
		return nil, err
	}
	m := v.Meta
	hosts := pyfmt.Obj{}
	for _, h := range m.HostsScanned {
		st := "ok"
		if m.HostsFailed.Has(h) {
			st = "unreachable"
		} else if m.ModuleErrors.Has(h) {
			st = "module errors"
		}
		var osName any
		if f, ok := v.Facts[h]; ok {
			osName = f.OS
		}
		e := pyfmt.O("status", st, "os", osName)
		if c := v.Hosts[h]; c != nil {
			e = append(e, pyfmt.KV{K: "P1", V: c.P1}, pyfmt.KV{K: "P2", V: c.P2}, pyfmt.KV{K: "P3", V: c.P3}, pyfmt.KV{K: "P4", V: c.P4}, pyfmt.KV{K: "cves", V: c.CVEs})
		}
		from := ""
		for _, r := range m.Sources[h] {
			from = max(from, r)
		}
		hosts = append(hosts, pyfmt.KV{K: h, V: append(e, pyfmt.KV{K: "data_from", V: from})})
	}
	errs := pyfmt.Obj{}
	for _, h := range m.HostsFailed.Keys {
		errs.Set(h, m.HostsFailed.M[h])
	}
	for _, h := range m.ModuleErrors.Keys {
		errs.Set(h, m.ModuleErrors.M[h])
	}
	top := []any{}
	for i := range v.Actions {
		if len(top) < 10 && deref(v.Actions[i].Priority) != "P4" {
			top = append(top, action(&v.Actions[i], "en"))
		}
	}
	var updated any
	if m.Finished != "" {
		updated = m.Finished
	}
	return pyfmt.O("org", org.ID, "env", env, "updated", updated, "packages_to_update", v.PlanCounts,
		"hosts", hosts, "errors", errs, "top_actions", top), nil
}

func (s *Server) listActions(a args) (any, error) {
	_, _, v, err := s.view(a)
	if err != nil {
		return nil, err
	}
	prios := a.strs("priority")
	if prios == nil {
		prios = []string{"P1", "P2", "P3"}
	}
	cats := a.strs("category")
	host := a.str("host")
	var rows []*report.Action
	for i := range v.Actions {
		x := &v.Actions[i]
		p := deref(x.Priority)
		if p == "" {
			p = "P4"
		}
		if slices.Contains(prios, p) && (cats == nil || slices.Contains(cats, x.Cat)) &&
			(!pyfmt.Truthy(a["host"]) || slices.Contains(x.Hosts, host)) && (!pyfmt.Truthy(a["rce_only"]) || (x.RCE != nil && *x.RCE != 0)) {
			rows = append(rows, x)
		}
	}
	n, err := a.limit(len(rows))
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, x := range rows[:n] {
		out = append(out, action(x, a.lang()))
	}
	return pyfmt.O("total", len(rows), "actions", out), nil
}

func (s *Server) getHost(a args) (any, error) {
	org, env, err := s.env(a)
	if err != nil {
		return nil, err
	}
	h := a.str("host")
	var cfg *config.Host
	for i := range org.Hosts {
		if x := &org.Hosts[i]; x.Name == h && x.Env == env {
			if _, isStr := a["host"].(string); isStr {
				cfg = x
			}
			break
		}
	}
	if cfg == nil {
		return nil, fmt.Errorf("no host '%s' in %s/%s", a.pyArg("host"), org.ID, env)
	}
	v, err := s.store.Current(org.ID, env)
	if err != nil {
		return nil, err
	}
	var facts, counts, hostErr any
	if f, ok := v.Facts[h]; ok {
		facts = f
	}
	if c := v.Hosts[h]; c != nil {
		counts = c
	}
	if e, ok := v.Meta.HostsFailed.Get(h); ok && e != "" {
		hostErr = e
	} else if e, ok := v.Meta.ModuleErrors.Get(h); ok {
		hostErr = e
	}
	acts := []any{}
	for i := range v.Actions {
		if slices.Contains(v.Actions[i].Hosts, h) {
			acts = append(acts, action(&v.Actions[i], a.lang()))
		}
	}
	out := pyfmt.O("host", h, "address", cfg.Address, "group", cfg.Group, "role", cfg.Role, "exposure", cfg.Exposure,
		"route", prompt.Route(org, cfg), "facts", facts, "packages_to_update", counts, "error", hostErr, "actions", acts)
	var bp []report.BackportedRow
	for _, r := range v.Backported {
		if r.Host == h {
			bp = append(bp, r)
		}
	}
	if len(bp) > 0 { // matched by version, but the installed build already has the fix: not in actions / counts
		n := 0
		pk := []any{}
		for i, r := range bp {
			n += r.CVEs
			if i < 30 {
				pk = append(pk, pyfmt.O("pkg", r.Pkg, "installed", r.Installed, "cves", r.CVEs, "ids", r.IDs))
			}
		}
		out = append(out, pyfmt.KV{K: "already_fixed_backport", V: pyfmt.O("cves", n, "packages", pk)})
	}
	if acc := s.store.HostData(org.ID, env, "access", h); len(acc) > 0 {
		L := asMap(acc.Get("logins"))
		keys := list(acc.Get("keys"))
		kd := []any{}
		for _, k := range keys {
			kd = append(kd, pick(k, "user", "type", "fp", "comment"))
		}
		logins := []any{}
		for _, x := range head(list(L.Get("accepted")), 30) {
			logins = append(logins, pick(x, "user", "ip", "method", "count", "last"))
		}
		att := []any{}
		for _, x := range head(list(L.Get("attackers")), 10) {
			att = append(att, pick(x, "ip", "n", "first", "last", "users"))
		}
		out = append(out, pyfmt.KV{K: "ssh", V: pyfmt.O("password_auth", acc.Get("password_auth"), "permit_root_login", asMap(acc.Get("sshd")).Get("permitrootlogin"),
			"users_with_password", acc.Get("users_with_password"), "keys", len(keys), "keys_detail", kd, "logins_30d", logins,
			"failed_total", L.Get("failed_total"), "attacker_ips", L.Get("failed_ips"), "last_attack", L.Get("failed_last"),
			"top_attackers", att, "not_readable", acc.Get("denied"))})
	}
	if exp := s.store.HostData(org.ID, env, "exposure", h); len(exp) > 0 {
		pub := []any{}
		for _, x := range list(exp.Get("listen")) {
			if pyfmt.Truthy(asMap(x).Get("public")) {
				pub = append(pub, x)
			}
		}
		out = append(out, pyfmt.KV{K: "network", V: pyfmt.O("public_ips", exp.Get("public"), "public_ips_missing_in_config", exp.Get("unlisted_public"),
			"listening_public", pub, "firewall", exp.Get("firewall"), "not_readable", exp.Get("denied"))})
	}
	if hl := s.store.HostData(org.ID, env, "health", h); len(hl) > 0 {
		var inodes any
		best := math.Inf(-1)
		for _, x := range list(hl.Get("inodes")) {
			u := asMap(x).Get("use")
			if f, ok := num(u); ok && f > best {
				best, inodes = f, u
			}
		}
		dm, jr := asMap(hl.Get("dmesg")), asMap(hl.Get("journal"))
		out = append(out, pyfmt.KV{K: "health", V: pyfmt.O("disks", hl.Get("disks"), "inodes_max", inodes, "memory", hl.Get("mem"), "load", hl.Get("load"),
			"failed_units", hl.Get("failed_units"), "kernel_log", dm.Get("classes"), "journal_errors_7d", jr.Get("errors_7d"),
			"journal_top", jr.Get("top"), "time", hl.Get("time"), "not_readable", hl.Get("denied"))})
	}
	return out, nil
}

var searchKeys = []string{"host", "pkg", "target", "installed", "fixed", "fix_state", "repo_version", "cves", "cve_top",
	"priority", "due", "kev", "preauth_rce", "inactive"}

func (s *Server) searchPackages(a args) (any, error) {
	_, _, v, err := s.view(a)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(a.str("query"))
	host := a.str("host")
	var rows []*report.PlanRow
	for i := range v.Plan {
		r := &v.Plan[i]
		if pyfmt.Truthy(a["host"]) && r.Host != host {
			continue
		}
		if strings.Contains(strings.ToLower(r.Pkg), q) || strings.Contains(strings.ToLower(r.Target), q) ||
			slices.ContainsFunc(r.CVETop, func(c string) bool { return strings.Contains(strings.ToLower(c), q) }) {
			rows = append(rows, r)
		}
	}
	n, err := a.limit(len(rows))
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, r := range rows[:n] {
		vals := map[string]any{"host": r.Host, "pkg": r.Pkg, "target": r.Target, "installed": r.Installed, "fixed": r.Fixed,
			"fix_state": ptr(r.FixState), "repo_version": ptr(r.RepoVersion), "cves": r.CVEs, "cve_top": r.CVETop,
			"priority": ptr(r.Priority), "due": ptr(r.Due), "kev": r.KEV, "preauth_rce": r.PreauthRCE, "inactive": r.Inactive}
		var o pyfmt.Obj
		for _, k := range searchKeys {
			x := vals[k]
			if l, isList := x.([]string); isList { // Python keeps [] here: only None, "", False (and 0) are dropped
				if l == nil {
					l = []string{}
				}
				o = append(o, pyfmt.KV{K: k, V: l})
			} else if pyfmt.Truthy(x) {
				o = append(o, pyfmt.KV{K: k, V: x})
			}
		}
		out = append(out, o)
	}
	return pyfmt.O("total", len(rows), "packages", out), nil
}

var errNoActions = errors.New("none of the action_ids found — take ids from list_actions")

func (s *Server) fixPrompt(a args) (any, error) {
	org, env, v, err := s.view(a)
	if err != nil {
		return nil, err
	}
	text := prompt.Build(org, env, v, a.strs("action_ids"), a.lang())
	if text == "" {
		return nil, errNoActions
	}
	return text, nil
}

func (s *Server) fixPlan(a args) (any, error) {
	org, env, v, err := s.view(a)
	if err != nil {
		return nil, err
	}
	p := remediate.BuildPlan(org, env, v, a.strs("action_ids"), a.lang())
	if len(p.Steps) == 0 && len(p.Manual) == 0 {
		return nil, errNoActions
	}
	return p, nil
}

func (s *Server) listRuns(a args) (any, error) {
	org, env, err := s.env(a)
	if err != nil {
		return nil, err
	}
	return s.store.Runs(org.ID, env), nil
}

// --- loosely typed view data -----------------------------------------------------------------------------------

func asMap(v any) pyfmt.Obj { m, _ := v.(pyfmt.Obj); return m }
func list(v any) []any      { l, _ := v.([]any); return l }

func head(l []any, n int) []any { return l[:min(n, len(l))] }

// pick: {k: x[k] for k in keys} (missing keys as null).
func pick(x any, keys ...string) pyfmt.Obj {
	m := asMap(x)
	o := make(pyfmt.Obj, len(keys))
	for i, k := range keys {
		o[i] = pyfmt.KV{K: k, V: m.Get(k)}
	}
	return o
}

func ptr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func num(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		var f float64
		_, err := fmt.Sscan(strings.TrimSpace(t), &f)
		return math.Trunc(f), err == nil && f == math.Trunc(f)
	}
	return 0, false
}
