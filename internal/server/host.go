package server

import (
	"encoding/json"
	"path/filepath"
	"slices"

	"github.com/mikekosulin/kanareika/internal/tree"
)

// hostFixes: what /api/host answers. ID: the host's node in the tree grouped by host ("" when nothing is open on
// it); its fixes' ids work with /api/node?by=host&id=, which has their CVEs, why, due and the commands for this
// host.
type hostFixes struct {
	ID    string       `json:"id"`
	Node  *tree.Node   `json:"node,omitempty"`
	Fixes []*tree.Node `json:"fixes"`
	// Details: with ?detail=1, each fix's details (as /api/node gives them), in the order of Fixes: what an interface
	// that shows them all at once (the TUI's card, MCP) needs in one request
	Details []*tree.Detail `json:"details,omitempty"`
}

// apiHost: one server's fixes (?host=, with ?org, ?env, ?run; ?detail=1 with each one's details): every package
// update, image rebuild and setting open on it, as the tree grouped by host has them, an image with what inside it
// needs the update. The filters of the lists don't apply: the server's page shows all of it.
func (s *Server) apiHost(q query) (any, error) {
	name := q.get("host")
	if name == "" {
		return nil, badRequest("host is required")
	}
	in, err := s.treeInput(q)
	if err != nil {
		return nil, err
	}
	t := in.tree(tree.Opts{By: tree.ByHost, Backported: q.get("backported") == "1", Today: today()})
	out := hostFixes{Fixes: []*tree.Node{}}
	if n := t.Host(name); n != nil {
		c := *n
		c.Kids = nil
		out.ID, out.Node, out.Fixes = n.ID, &c, t.Under(n.ID, 1)
		if q.get("detail") == "1" {
			for _, f := range out.Fixes {
				out.Details = append(out.Details, tree.Describe(t.Find(f.ID), tree.Hosts(in.view.Facts), in.view, today()))
			}
		}
	}
	return out, nil
}

// hostChange: a finding of the server that appeared or went in a run (view.json's new / resolved rows).
type hostChange struct {
	Target   string   `json:"target"`
	Pkg      string   `json:"pkg"`
	IDs      []string `json:"ids"`
	Priority string   `json:"priority"`
	KEV      bool     `json:"kev"`
	Title    string   `json:"title"`
	Count    int      `json:"count"`
	Host     string   `json:"host"`
}

// hostRun: one run as the server saw it: scanned (ok) or not reached (failed), and what changed on it.
type hostRun struct {
	RunID    string       `json:"run_id"`
	Finished any          `json:"finished"`
	State    string       `json:"state"` // ok, failed
	New      []hostChange `json:"new"`
	Resolved []hostChange `json:"resolved"`
}

// maxHostRuns: the most runs /api/host/history reads (each is a view to parse).
const maxHostRuns = 30

// apiHostHistory: one server's runs, newest first (?host=, ?org, ?env): each finished run that included it, whether
// it was reached, and what appeared on it and what went since the run before. At most maxHostRuns runs.
func (s *Server) apiHostHistory(q query) (any, error) {
	name := q.get("host")
	if name == "" {
		return nil, badRequest("host is required")
	}
	o, env, err := s.orgEnv(q)
	if err != nil {
		return nil, err
	}
	group := ""
	for _, h := range o.Hosts {
		if h.Env == env && h.Name == name {
			group = h.Group
		}
	}
	dir := s.envDir(o.ID, env)
	rs := runs(dir)
	out := []hostRun{}
	for i := len(rs) - 1; i >= 0 && len(out) < maxHostRuns; i-- {
		r := rs[i]
		if r.State != "done" || !inSelection(r.Selection, name, group) {
			continue
		}
		h := hostRun{RunID: r.RunID, Finished: r.Finished, State: "ok", New: []hostChange{}, Resolved: []hostChange{}}
		if slices.Contains(r.Failed, name) {
			h.State = "failed"
		}
		if b, err := s.historyView(filepath.Join(dir, r.RunID)); err == nil {
			var v struct {
				New, Resolved *struct{ Rows []hostChange }
			}
			if json.Unmarshal(b, &v) == nil {
				h.New, h.Resolved = rowsOf(v.New, name), rowsOf(v.Resolved, name)
			}
		}
		out = append(out, h)
	}
	return map[string]any{"runs": out}, nil
}

func rowsOf(c *struct{ Rows []hostChange }, host string) []hostChange {
	out := []hostChange{}
	if c != nil {
		for _, r := range c.Rows {
			if r.Host == host {
				out = append(out, r)
			}
		}
	}
	return out
}

// inSelection: a run's selection (run.json: hosts, groups) included the host; an empty one is the whole env.
func inSelection(sel any, host, group string) bool {
	m, _ := sel.(map[string]any)
	list := func(k string) []string {
		var out []string
		xs, _ := m[k].([]any)
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	hosts, groups := list("hosts"), list("groups")
	if len(hosts) == 0 && len(groups) == 0 {
		return true
	}
	return slices.Contains(hosts, host) || group != "" && slices.Contains(groups, group)
}
