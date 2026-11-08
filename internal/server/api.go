package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/ipinfo"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/report"
)

// notFound is Python's LookupError: answered with 404 {"error": msg}.
type notFound string

func (e notFound) Error() string { return string(e) }

// orgState: the org configs as last loaded; replaced as a whole on reload, so readers need no lock.
type orgState struct {
	orgs   []*config.Org
	errors []string
	byID   map[string]*config.Org
}

func (s *Server) reload() {
	st := &orgState{errors: []string{}, byID: map[string]*config.Org{}}
	if l, err := config.NewLoader(s.paths); err != nil {
		st.errors = []string{err.Error()}
	} else {
		st.orgs, st.errors = l.LoadAll()
		if st.errors == nil {
			st.errors = []string{}
		}
	}
	for _, o := range st.orgs {
		st.byID[o.ID] = o
	}
	s.state.Store(st)
}

func (s *Server) orgEnv(q query) (*config.Org, string, error) {
	o := s.state.Load().byID[q.get("org")]
	env := q.get("env")
	if o == nil || !slices.Contains(o.Envs(), env) {
		return nil, "", notFound("unknown org/env")
	}
	return o, env, nil
}

func (s *Server) envDir(org, env string) string { return report.EnvDir(s.paths, org, env) }

// /api/orgs re-reads orgs/ (the page calls it on load), so edited org files show up without a restart.
func (s *Server) apiOrgs(query) (any, error) {
	s.reload()
	st := s.state.Load()
	type envRow struct {
		Env     string   `json:"env"`
		Hosts   int      `json:"hosts"`
		Last    *runInfo `json:"last"`
		Running *runInfo `json:"running"`
	}
	type orgRow struct {
		ID   string   `json:"id"`
		Name string   `json:"name"`
		Envs []envRow `json:"envs"`
	}
	out := []orgRow{}
	for _, o := range st.orgs {
		row := orgRow{ID: o.ID, Name: o.Name(), Envs: []envRow{}}
		for _, env := range o.Envs() {
			e := envRow{Env: env}
			for _, h := range o.Hosts {
				if h.Env == env {
					e.Hosts++
				}
			}
			rs := runs(s.envDir(o.ID, env))
			for i := range rs {
				if rs[i].State == "done" {
					e.Last = &rs[i]
				}
			}
			for i := len(rs) - 1; i >= 0; i-- {
				if rs[i].State == "running" {
					e.Running = &rs[i]
					break
				}
			}
			row.Envs = append(row.Envs, e)
		}
		out = append(out, row)
	}
	return map[string]any{"orgs": out, "errors": st.errors}, nil
}

// isPublic: the configured address is a public IP, the host is reached from the internet directly. DNS names
// are not decided here (the exposure module still reports interface IPs).
func isPublic(address string) bool {
	a, err := parseAddr(address)
	return err == nil && ipinfo.IsGlobal(a)
}

// modules enabled on a host, in the order of config.HostModules (the profiles list them in that order).
func modules(c config.Checks) []string {
	out := []string{}
	for _, m := range config.HostModules {
		if c.Enabled(m) {
			out = append(out, m)
		}
	}
	var extra []string
	for m := range c {
		if !slices.Contains(config.HostModules, m) && c.Enabled(m) {
			extra = append(extra, m)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Server) apiEnv(q query) (any, error) {
	o, env, err := s.orgEnv(q)
	if err != nil {
		return nil, err
	}
	hosts := []map[string]any{}
	for _, h := range o.Hosts {
		if h.Env != env {
			continue
		}
		hosts = append(hosts, map[string]any{"name": h.Name, "group": h.Group, "role": h.Role,
			"exposure": h.Exposure, "address": h.Address, "port": h.Port, "user": h.User, "jump": nullable(h.Jump), "public": isPublic(h.Address),
			"modules": modules(h.Checks)})
	}
	rs := runs(s.envDir(o.ID, env))
	var live any
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].State == "running" || rs[i].State == "stale" {
			if st := status(filepath.Join(s.envDir(o.ID, env), rs[i].RunID)); st != nil {
				live = st
			}
			break
		}
	}
	c := o.Consent()
	return map[string]any{"org": o.ID, "env": env, "name": o.Name(), "hosts": hosts, "runs": rs, "live": live,
		"consent": map[string]any{"valid_until": c["valid_until"], "external_scan": c["external_scan"]}}, nil
}

// runDir resolves ?run= to a finished run, or to current/ (brought up to date first).
func (s *Server) runDir(q query) (string, error) {
	o, env, err := s.orgEnv(q)
	if err != nil {
		return "", err
	}
	id := q.get("run")
	if id == report.Current {
		s.mu.Lock() // fold in runs that finished since (also bootstraps current/ for old reports)
		cur, err := report.UpdateCurrent(s.envDir(o.ID, env), false, false)
		s.mu.Unlock()
		if err != nil {
			return "", err
		}
		if cur == "" {
			return "", notFound("no runs")
		}
		return cur, nil
	}
	for _, r := range runs(s.envDir(o.ID, env)) {
		if r.RunID == id && r.State == "done" {
			return filepath.Join(s.envDir(o.ID, env), id), nil
		}
	}
	return "", notFound("unknown run")
}

func (s *Server) apiRun(q query) (any, error) {
	dir, err := s.runDir(q)
	if err != nil {
		return nil, err
	}
	b, err := s.view(dir)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

type viewKey struct {
	dir   string
	mtime int64
}

// view: the run's view.json, cached by its mtime. Runs written before the current view version get the view
// rebuilt once, on first open, and stored (with plan_counts added to run.json) so the next open is cheap.
// current/ is never rebuilt here: UpdateCurrent owns it.
func (s *Server) view(dir string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vf := filepath.Join(dir, "view.json")
	key := viewKey{dir: dir}
	if st, err := os.Stat(vf); err == nil {
		key.mtime = st.ModTime().UnixNano()
	}
	for _, e := range s.views {
		if e.key == key {
			return e.body, nil
		}
	}
	body, ok := storedView(vf, filepath.Base(dir) == report.Current)
	if !ok {
		meta, findings, err := report.LoadRun(dir)
		if err != nil {
			return nil, err
		}
		var prev *report.Prev
		if !report.IsPartial(meta) {
			if prev, err = report.PreviousRun(dir, true); err != nil {
				return nil, err
			}
		}
		v := report.BuildView(dir, meta, findings, prev)
		meta.PlanCounts = &v.PlanCounts
		meta.Totals = &v.Totals
		v.Meta = meta
		if body, err = marshalView(v); err != nil {
			return nil, err
		}
		// best effort, as before: a read-only reports/ still gets the view, just not stored
		if report.WriteView(dir, v) == nil {
			_ = report.WriteMeta(dir, meta)
		}
	}
	if len(s.views) > 8 {
		s.views = s.views[1:]
	}
	s.views = append(s.views, cachedView{key, body})
	return body, nil
}

// marshalView encodes a rebuilt view (a variable so tests can make it fail).
var marshalView = pyfmt.Marshal

// storedView: view.json if it is usable as is: valid, and of the current version (any version for current/).
func storedView(path string, current bool) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var head struct {
		Version any `json:"version"`
	}
	if json.Unmarshal(b, &head) != nil || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return nil, false
	}
	if !current {
		if n, ok := head.Version.(float64); !ok || n != report.ViewVersion {
			return nil, false
		}
	}
	return b, true
}

// apiHostfile: raw per-host module output (e.g. firewall rules); only whitelisted files of a configured host.
func (s *Server) apiHostfile(q query) (any, error) {
	o, env, err := s.orgEnv(q)
	if err != nil {
		return nil, err
	}
	run, host, file := q.get("run"), q.get("host"), q.get("name")
	if !slices.Contains([]string{"exposure", "access", "health"}, file) || !name.MatchString(run) ||
		!name.MatchString(host) {
		return nil, notFound("bad request")
	}
	known := false
	for _, h := range o.Hosts {
		known = known || h.Env == env && h.Name == host
	}
	if !known {
		return nil, notFound("unknown host")
	}
	b, err := os.ReadFile(filepath.Join(s.envDir(o.ID, env), run, "hosts", host, file+".json"))
	if err != nil {
		return nil, notFound("no data")
	}
	if v, err := decode(b); err != nil || v == nil {
		return nil, notFound("no data")
	}
	return json.RawMessage(b), nil
}

func (s *Server) apiIPInfo(q query) (any, error) {
	return ipinfo.Lookup(q.list("ips", ipinfo.MaxIPs), s.state.Load().orgs), nil
}

func (s *Server) apiPrompt(q query) (any, error) {
	o, env, err := s.orgEnv(q)
	if err != nil {
		return nil, err
	}
	dir, err := s.runDir(q)
	if err != nil {
		return nil, err
	}
	b, err := s.view(dir)
	if err != nil {
		return nil, err
	}
	if s.prompt == nil {
		return nil, errNoPrompt
	}
	var v report.View
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	lang := q.get("lang")
	if lang == "" {
		lang = "en"
	}
	ids := q.list("ids", 200)
	if nodes := q.list("nodes", 200); len(nodes) > 0 { // tree nodes: the actions under them
		more, err := s.nodeActions(q, nodes)
		if err != nil {
			return nil, err
		}
		for _, id := range more {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	return map[string]string{"text": s.prompt(o, env, &v, ids, lang)}, nil
}

var errNoPrompt = errors.New("prompt builder not configured")

func (s *Server) apiI18n(query) (any, error) {
	return map[string]any{"langs": i18n.Langs(), "messages": i18n.Catalog()}, nil
}

// apiLog: the last 2000 lines of a run's log (also of a running scan).
func (s *Server) apiLog(q query) (any, error) {
	o, env, err := s.orgEnv(q)
	if err != nil {
		return nil, err
	}
	run := q.get("run")
	if !name.MatchString(run) {
		return nil, notFound("unknown run")
	}
	lines := []string{}
	if b, err := os.ReadFile(filepath.Join(s.envDir(o.ID, env), run, "run.log")); err == nil {
		lines = append(lines, pyfmt.Last(pyfmt.SplitLines(pyfmt.DecodeUTF8(b)), 2000)...)
	}
	return map[string]any{"lines": lines}, nil
}
