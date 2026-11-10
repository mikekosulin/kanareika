package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/lens"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/store"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// treeInput: a run's findings (from the store) and view, what trees are built from; kept per run directory, the
// last few, and loaded again when the view changes (a scan folded into current/).
type treeInput struct {
	dir   string
	mtime int64 // view.json's
	ready chan struct{}
	err   error
	set   *tree.Set
	n     int // findings
	view  *report.View

	mu    sync.Mutex
	built map[string]*tree.Tree // trees of this input by grouping, filters, query and inventory: a node's details,
	// its kids or a switch back to a grouping don't build it again
}

// Runs kept in memory: the ones looked at last, while they hold keepFindings findings together (a large
// environment's current/ alone is about a million: then only it), and up to keepInputs of them.
const (
	keepInputs   = 3
	keepFindings = 1_200_000
	keepTrees    = 8 // trees kept per run (each holds its rows' findings)
)

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
	var in *treeInput
	for i, c := range s.trees {
		if c.dir == dir && c.mtime == mtime && c.err == nil {
			in = c
			s.trees = append(append([]*treeInput{c}, s.trees[:i]...), s.trees[i+1:]...) // most recent first
			break
		}
	}
	if in == nil {
		in = &treeInput{dir: dir, mtime: mtime, ready: make(chan struct{})}
		s.trees = slices.DeleteFunc(s.trees, func(c *treeInput) bool { return c.dir == dir })
		s.trees = append([]*treeInput{in}, s.trees...)
		s.trees = trim(s.trees)
		go s.loadInput(in, b) // requests asking meanwhile wait for the same load
	}
	s.mu.Unlock()
	<-in.ready
	return in, in.err
}

func (s *Server) loadInput(in *treeInput, view []byte) {
	in.err = in.load(s.paths.Reports, view)
	close(in.ready)
	s.mu.Lock()
	s.trees = trim(s.trees) // now that its size is known
	s.mu.Unlock()
	debug.FreeOSMemory() // what reading it took goes back to the system now
}

func (in *treeInput) load(reports string, view []byte) error {
	var v report.View
	if err := json.Unmarshal(view, &v); err != nil {
		return err
	}
	fs, err := store.Load(context.Background(), reports, in.dir)
	if err != nil {
		return err
	}
	in.view, in.set, in.n = &v, tree.FromSet(fs), fs.Len()
	return nil
}

// trim: the inputs to keep (most recent first): the first always, the next while they fit in keepFindings.
// Inputs still loading count as nothing yet; they are trimmed when loaded.
func trim(ins []*treeInput) []*treeInput {
	n := 0
	for i, in := range ins {
		if i > 0 && (i >= keepInputs || n+in.loaded() > keepFindings) {
			clear(ins[i:]) // the array keeps what is past the length: those would stay in memory
			return ins[:i]
		}
		n += in.loaded()
	}
	return ins
}

// loaded: how many findings the input holds (0 while loading).
func (in *treeInput) loaded() int {
	select {
	case <-in.ready:
		return in.n
	default:
		return 0
	}
}

// today: the date "overdue" is judged by; tests replace it.
var today = func() string { return time.Now().UTC().Format(time.DateOnly) }

func treeOpts(q query) tree.Opts {
	return tree.Opts{By: q.get("by"), Filters: q.list("f", 10), Query: q.get("q"), Backported: q.get("backported") == "1",
		Today: today()}
}

// build: the tree of the query's grouping and filters, its levels made when asked for. ?all=1 with by=host: every
// host of the env (the server view), from the org file too, which is part of the key.
func (s *Server) build(q query, in *treeInput) (*tree.Tree, error) {
	o := treeOpts(q)
	if q.get("all") == "1" && o.By == tree.ByHost {
		org, env, err := s.orgEnv(q)
		if err != nil {
			return nil, err
		}
		o.All, o.Inventory = true, tree.Servers(org, env, in.view, in.set.Inventory())
	}
	return in.tree(o), nil
}

// tree: the tree of o over the input, built once per options.
func (in *treeInput) tree(o tree.Opts) *tree.Tree {
	inv, _ := json.Marshal(o.Inventory)
	key := strings.Join([]string{o.By, strings.Join(o.Filters, ","), o.Query, strconv.FormatBool(o.Backported), o.Today,
		strconv.FormatBool(o.All), string(inv)}, "\x00")
	in.mu.Lock()
	t := in.built[key]
	in.mu.Unlock()
	if t != nil {
		return t
	}
	t = tree.BuildSet(in.set, tree.Hosts(in.view.Facts), o)
	in.mu.Lock()
	if in.built == nil || len(in.built) >= keepTrees {
		in.built = map[string]*tree.Tree{}
	}
	in.built[key] = t
	in.mu.Unlock()
	return t
}

// apiTree: the env's findings as a tree (?by=fix|cve|host, ?f=kev,rce,epss,front,ready,nofix,overdue, ?q=,
// ?backported=1, ?all=1 with by=host for every host of the env). ?levels=N: only N levels of kids under the top
// rows (0: the top rows), the rest counted in each node's "more"; ?under=id: the kids of that node instead, with
// ?levels as well. ?offset=&limit=: one page of the rows ("rows": how many there are). By CVE the whole tree is
// over a hundred MB on a few hosts, its top rows a few.
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
	offset, _ := strconv.Atoi(q.get("offset"))
	limit, _ := strconv.Atoi(q.get("limit"))
	paged := q.get("offset") != "" || q.get("limit") != ""
	if id := q.get("under"); id != "" {
		n := t.Find(id)
		if n == nil {
			return nil, notFound("unknown node")
		}
		c := *t
		c.Nodes = n.Children()
		if paged {
			c = *c.Page(offset, limit)
		}
		if levels >= 0 {
			c.Nodes = (&tree.Tree{Nodes: c.Nodes}).Shallow(levels).Nodes
		} else {
			c.Nodes = (&tree.Tree{Nodes: c.Nodes}).Full().Nodes
		}
		return &c, nil
	}
	if paged {
		t = t.Page(offset, limit)
	}
	if levels >= 0 {
		return t.Shallow(levels), nil
	}
	return t.Full(), nil
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
	o := tree.Opts{By: tree.ByHost, All: true, Inventory: tree.Servers(org, env, in.view, in.set.Inventory()), Today: today()}
	return lens.Build(l, lens.Input{Servers: in.tree(o), View: in.view, Findings: in.set.Select(lens.Reads), Lang: q.get("lang")}), nil
}
