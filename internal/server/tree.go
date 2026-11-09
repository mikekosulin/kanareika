package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// treeInput: the run's findings and view, what a tree is built from; cached by the view's mtime like views.
type treeInput struct {
	dir      string
	mtime    int64
	findings []finding.Finding
	view     *report.View
}

func (s *Server) treeInput(q query) (*treeInput, error) {
	dir, err := s.runDir(q)
	if err != nil {
		return nil, err
	}
	b, err := s.view(dir) // brings an old run's view up to date, as /api/run does
	if err != nil {
		return nil, err
	}
	var mtime int64
	if st, err := os.Stat(filepath.Join(dir, "view.json")); err == nil {
		mtime = st.ModTime().UnixNano()
	}
	s.mu.Lock()
	if c := s.trees; c != nil && c.dir == dir && c.mtime == mtime {
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()
	fs, err := report.LoadFindings(dir)
	if err != nil {
		return nil, err
	}
	var v report.View
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	in := &treeInput{dir: dir, mtime: mtime, findings: fs, view: &v}
	s.mu.Lock()
	s.trees = in
	s.mu.Unlock()
	return in, nil
}

// today: the date "overdue" is judged by; tests replace it.
var today = func() string { return time.Now().UTC().Format(time.DateOnly) }

func treeOpts(q query) tree.Opts {
	return tree.Opts{By: q.get("by"), Filters: q.list("f", 10), Query: q.get("q"), Backported: q.get("backported") == "1",
		Today: today()}
}

// build: the tree of the query's grouping and filters. ?all=1 with by=host: every host of the env (the server
// view), also the clean, failed and not scanned ones.
func (s *Server) build(q query, in *treeInput) (*tree.Tree, error) {
	o := treeOpts(q)
	if q.get("all") == "1" && o.By == tree.ByHost {
		org, env, err := s.orgEnv(q)
		if err != nil {
			return nil, err
		}
		o.All, o.Inventory = true, tree.Servers(org, env, in.view, in.findings)
	}
	return tree.Build(in.findings, tree.Hosts(in.view.Facts), o), nil
}

// apiTree: the env's findings as a tree (?by=fix|cve|host, ?f=kev,rce,epss,front,ready,nofix,overdue, ?q=,
// ?backported=1, ?all=1 with by=host for every host of the env).
func (s *Server) apiTree(q query) (any, error) {
	in, err := s.treeInput(q)
	if err != nil {
		return nil, err
	}
	return s.build(q, in)
}

// apiNode: the details of one node (?id=, with the same grouping and filters the tree was built with).
func (s *Server) apiNode(q query) (any, error) {
	in, err := s.treeInput(q)
	if err != nil {
		return nil, err
	}
	t, err := s.build(q, in)
	if err != nil {
		return nil, err
	}
	n := t.Find(q.get("id"))
	if n == nil {
		return nil, notFound("unknown node")
	}
	return tree.Describe(n, tree.Hosts(in.view.Facts), in.view, today()), nil
}

// nodeActions: the view actions under the given nodes (the agent task is built from actions).
func (s *Server) nodeActions(q query, ids []string) ([]string, error) {
	in, err := s.treeInput(q)
	if err != nil {
		return nil, err
	}
	t, err := s.build(q, in)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, id := range ids {
		if n := t.Find(id); n != nil {
			for _, a := range tree.Describe(n, tree.Hosts(in.view.Facts), in.view, today()).Actions {
				if !slices.Contains(out, a) {
					out = append(out, a)
				}
			}
		}
	}
	return out, nil
}
