package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/report"
	kdb "github.com/mikekosulin/kanareika/internal/store"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// Store is the read-only data access MCP needs: orgs (reloaded on every call, so edits to orgs/ show up without a
// restart), the run list of an environment and its current/ view. It mirrors the dashboard's Api (orgs overview,
// env runs, run view) for these three; kept here so MCP does not depend on the HTTP server package.
type Store struct {
	Paths config.Paths

	mu     sync.Mutex
	orgs   []*config.Org
	byID   map[string]*config.Org
	errors []string
	views  map[string]cached // path of view.json -> decoded view (one per env: current/ only)
	data   *findingsCache    // the last environment's findings (an assistant asks about one at a time)
}

// findingsCache: an environment's current findings as the database holds them, the set trees are built from.
type findingsCache struct {
	dir   string
	mtime time.Time // of view.json (written after the findings)
	set   *tree.Set
}

type cached struct {
	mtime time.Time
	view  *report.View
	raw   map[string]map[string]json.RawMessage // access / health / exposure -> host -> as stored (for key order)
}

func NewStore(p config.Paths) *Store { return &Store{Paths: p, views: map[string]cached{}} }

// Findings: the current findings of org's env (from reports/kanareika.db) as a tree set; the last environment's
// are kept until its view changes.
func (s *Store) Findings(org, env string) (*tree.Set, error) {
	dir := filepath.Join(report.EnvDir(s.Paths, org, env), report.Current)
	var mtime time.Time
	if st, err := os.Stat(filepath.Join(dir, "view.json")); err == nil {
		mtime = st.ModTime()
	}
	s.mu.Lock()
	c := s.data
	s.mu.Unlock()
	if c != nil && c.dir == dir && c.mtime.Equal(mtime) {
		return c.set, nil
	}
	s.mu.Lock()
	s.data = nil // the last one goes before the next is read
	s.mu.Unlock()
	fs, err := kdb.Load(context.Background(), s.Paths.Reports, dir)
	if err != nil {
		return nil, err
	}
	c = &findingsCache{dir: dir, mtime: mtime, set: tree.FromSet(fs)}
	s.mu.Lock()
	s.data = c
	s.mu.Unlock()
	return c.set, nil
}

// Reload reads every org file again; a broken setup is reported as errors, not a failure.
func (s *Store) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := config.NewLoader(s.Paths)
	if err != nil {
		s.orgs, s.errors = nil, []string{err.Error()}
	} else {
		s.orgs, s.errors = l.LoadAll()
	}
	if s.errors == nil {
		s.errors = []string{}
	}
	s.byID = map[string]*config.Org{}
	for _, o := range s.orgs {
		s.byID[o.ID] = o
	}
}

func (s *Store) Org(id string) *config.Org {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byID[id]
}

// OrgIDs, sorted.
func (s *Store) OrgIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, o := range s.orgs {
		out = append(out, o.ID)
	}
	slices.Sort(out)
	return out
}

// staleAfter: a running scan's heartbeat is 5s; older than this = the process is gone.
const staleAfter = 60 * time.Second

// Now: the clock stale detection reads; tests fix it to the fixture's time.
var Now = time.Now

var runName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Run is one line of an environment's run history (from run.json, or status.json while it runs).
type Run struct {
	RunID       string `json:"run_id"`
	State       string `json:"state"` // done | running | stale | failed …, as status.json says
	Started     any    `json:"started"`
	Finished    any    `json:"finished"`
	Counts      any    `json:"counts"`
	PlanCounts  any    `json:"plan_counts"`
	Totals      any    `json:"totals,omitempty"` // fixes to apply and unique CVEs (report.Totals); runs before 0.5 have none
	HostsTotal  int    `json:"hosts_total"`
	HostsFailed int    `json:"hosts_failed"`
	Selection   any    `json:"selection"`
	Partial     bool   `json:"partial"`
}

// readMap decodes a JSON object keeping numbers as written; nil when missing or broken.
func readMap(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if d.Decode(&m) != nil {
		return nil
	}
	return m
}

func status(runDir string) map[string]any {
	st := readMap(filepath.Join(runDir, "status.json"))
	if st != nil && st["state"] == "running" {
		u, _ := st["updated"].(string)
		t, err := time.Parse(time.RFC3339Nano, u)
		if err != nil || Now().Sub(t) > staleAfter {
			st["state"] = "stale"
		}
	}
	return st
}

// Runs of an environment, oldest first; current/ is not a run.
func (s *Store) Runs(org, env string) []Run {
	d := report.EnvDir(s.Paths, org, env)
	ents, err := os.ReadDir(d)
	out := []Run{}
	if err != nil {
		return out
	}
	for _, e := range ents {
		if !e.IsDir() || !runName.MatchString(e.Name()) || e.Name() == report.Current {
			continue
		}
		dir := filepath.Join(d, e.Name())
		meta, st := readMap(filepath.Join(dir, "run.json")), status(dir)
		if len(meta) == 0 && len(st) == 0 {
			continue
		}
		state, _ := st["state"].(string)
		if state == "" {
			state = "done"
		}
		if len(meta) > 0 && (state == "running" || state == "stale") {
			state = "done"
		}
		src := meta
		if len(src) == 0 {
			src = st
		}
		counts := meta["counts"]
		if !pyfmt.Truthy(counts) {
			counts = st["counts"]
		}
		hosts := meta["hosts_scanned"]
		if !pyfmt.Truthy(hosts) {
			hosts = st["hosts"]
		}
		hl, _ := hosts.([]any)
		failed, _ := meta["hosts_failed"].(map[string]any)
		sel, _ := meta["selection"].(map[string]any)
		out = append(out, Run{RunID: e.Name(), State: state, Started: src["started"], Finished: src["finished"],
			Counts: counts, PlanCounts: meta["plan_counts"], Totals: pyfmt.Or(meta["totals"], st["totals"]), HostsTotal: len(hl), HostsFailed: len(failed),
			Selection: meta["selection"], Partial: pyfmt.Truthy(sel["hosts"]) || pyfmt.Truthy(sel["groups"]) || pyfmt.Truthy(sel["modules"])})
	}
	return out
}

// Overview: every org with its environments, host counts, the last finished run and a running one.
func (s *Store) Overview() any {
	s.Reload()
	s.mu.Lock()
	orgs, errs := s.orgs, s.errors
	s.mu.Unlock()
	out := []any{}
	for _, o := range orgs {
		envs := []any{}
		for _, env := range o.Envs() {
			runs := s.Runs(o.ID, env)
			n := 0
			for _, h := range o.Hosts {
				if h.Env == env {
					n++
				}
			}
			var last, running any
			for i := range runs {
				if runs[i].State == "done" {
					last = runs[i]
				}
			}
			for i := len(runs) - 1; i >= 0; i-- {
				if runs[i].State == "running" {
					running = runs[i]
					break
				}
			}
			envs = append(envs, pyfmt.O("env", env, "hosts", n, "last", last, "running", running))
		}
		out = append(out, pyfmt.O("id", o.ID, "name", o.Name(), "envs", envs))
	}
	return pyfmt.O("orgs", out, "errors", errs)
}

var errNoRuns = errors.New("no runs")

// updateCurrent folds finished runs into current/; a variable so tests can hand Current a snapshot that vanished.
var updateCurrent = report.UpdateCurrent

// Current: the view of reports/<org>/<env>/current, after folding in runs that finished since. While a scan holds
// the environment, the existing snapshot is used as is (the scan updates it at the end).
func (s *Store) Current(org, env string) (*report.View, error) {
	cur, err := updateCurrent(report.EnvDir(s.Paths, org, env), false, false)
	if err != nil {
		return nil, err
	}
	if cur == "" {
		return nil, errNoRuns
	}
	path := filepath.Join(cur, "view.json")
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	c, ok := s.views[path]
	s.mu.Unlock()
	if ok && c.mtime.Equal(fi.ModTime()) {
		return c.view, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber() // passed-through host data keeps its numbers as written
	var v report.View
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var raw map[string]map[string]json.RawMessage
	var sections struct{ Access, Health, Exposure map[string]json.RawMessage }
	if json.Unmarshal(b, &sections) == nil {
		raw = map[string]map[string]json.RawMessage{"access": sections.Access, "health": sections.Health, "exposure": sections.Exposure}
	}
	s.mu.Lock()
	s.views[path] = cached{fi.ModTime(), &v, raw}
	s.mu.Unlock()
	return &v, nil
}

// HostData: one host's access / health / exposure data of the current view with the keys in stored order (tools
// pass it through, and the Python server lists it as stored); nil when there is none. Call after Current.
func (s *Store) HostData(org, env, section, host string) pyfmt.Obj {
	s.mu.Lock()
	c := s.views[filepath.Join(report.EnvDir(s.Paths, org, env), report.Current, "view.json")]
	s.mu.Unlock()
	b := c.raw[section][host]
	if len(b) == 0 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, _ := pyfmt.Decode(d) // b is a value of a view.json that decoded as a whole: always valid JSON
	m, _ := v.(pyfmt.Obj)
	return m
}
