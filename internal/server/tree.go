package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/lens"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// treeInput: the run's findings and view, what a tree is built from; cached by the view's mtime like views.
type treeInput struct {
	dir      string
	mtime    int64
	findings []finding.Finding
	view     *report.View

	mu    sync.Mutex
	built map[string]*tree.Tree // trees of this input by grouping, filters and query: a node's details or a switch
	// back to a grouping don't build it again (by CVE that takes most of a second on a few hosts)
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
	all := q.get("all") == "1" && o.By == tree.ByHost
	key := strings.Join([]string{o.By, strings.Join(o.Filters, ","), o.Query, strconv.FormatBool(o.Backported), o.Today}, "\x00")
	if !all { // the server view reads the org file too, which can change under the same run: never cached
		in.mu.Lock()
		t := in.built[key]
		in.mu.Unlock()
		if t != nil {
			return t, nil
		}
	}
	if all {
		org, env, err := s.orgEnv(q)
		if err != nil {
			return nil, err
		}
		o.All, o.Inventory = true, tree.Servers(org, env, in.view, in.findings)
	}
	t := tree.Build(in.findings, tree.Hosts(in.view.Facts), o)
	if !all {
		in.mu.Lock()
		if in.built == nil || len(in.built) >= 16 {
			in.built = map[string]*tree.Tree{}
		}
		in.built[key] = t
		in.mu.Unlock()
	}
	return t, nil
}

// apiTree: the env's findings as a tree (?by=fix|cve|host, ?f=kev,rce,epss,front,ready,nofix,overdue, ?q=,
// ?backported=1, ?all=1 with by=host for every host of the env). ?levels=N: only N levels of kids under the top
// rows (0: the top rows), the rest counted in each node's "more"; ?under=id: the kids of that node instead, with
// ?levels as well. By CVE the whole tree is over a hundred MB on a few hosts, its top rows a few.
func (s *Server) apiTree(q query) (any, error) {
	in, err := s.treeInput(q)
	if err != nil {
		return nil, err
	}
	t, err := s.build(q, in)
	if err != nil {
		return nil, err
	}
	levels, err := strconv.Atoi(q.get("levels"))
	if err != nil || levels < 0 {
		levels = -1
	}
	if id := q.get("under"); id != "" {
		n := t.Find(id)
		if n == nil {
			return nil, notFound("unknown node")
		}
		c := *t
		c.Nodes = n.Kids
		if levels >= 0 {
			c.Nodes = t.Under(id, levels)
		}
		return &c, nil
	}
	if levels >= 0 {
		return t.Shallow(levels), nil
	}
	return t, nil
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

// apiLens: the server view's per-host columns (?id=priorities|logins|network|health, ?run=, ?lang=): the lens list,
// the lens's columns and one row per host in the order and with the states of /api/tree?by=host&all=1.
func (s *Server) apiLens(q query) (any, error) {
	l := lens.Get(q.get("id"))
	if l == nil {
		return nil, notFound("unknown lens: " + strings.Join(lens.IDs(), ", "))
	}
	in, err := s.treeInput(q)
	if err != nil {
		return nil, err
	}
	org, env, err := s.orgEnv(q)
	if err != nil {
		return nil, err
	}
	o := tree.Opts{By: tree.ByHost, All: true, Inventory: tree.Servers(org, env, in.view, in.findings), Today: today()}
	return lens.Build(l, lens.Input{Servers: tree.Build(in.findings, tree.Hosts(in.view.Facts), o), View: in.view,
		Findings: in.findings, Lang: q.get("lang")}), nil
}
