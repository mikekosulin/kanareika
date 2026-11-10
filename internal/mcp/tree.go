package mcp

import (
	"errors"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/lens"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// mcpToday: the date overdue is judged by; tests replace it.
var mcpToday = func() string { return time.Now().UTC().Format(time.DateOnly) }

// treeOf: the env's current state as a tree, with the grouping and filters of the call.
func (s *Server) treeOf(a args) (*tree.Tree, tree.Hosts, *report.View, error) {
	org, env, v, err := s.view(a)
	if err != nil {
		return nil, nil, nil, err
	}
	set, err := s.store.Findings(org.ID, env)
	if err != nil {
		return nil, nil, nil, err
	}
	hosts := tree.Hosts(v.Facts)
	o := tree.Opts{By: a.str("by"), Filters: a.strs("filters"), Query: a.str("query"), Today: mcpToday()}
	if all, _ := a["all"].(bool); all && o.By == tree.ByHost {
		o.All, o.Inventory = true, tree.Servers(org, env, v, set.Inventory())
	}
	return tree.BuildSet(set, hosts, o), hosts, v, nil
}

// trimmed: a node without its subtree beyond depth (0: the node only).
func trimmed(n *tree.Node, depth int) *tree.Node {
	c := *n
	c.Kids = nil
	if depth > 0 {
		for _, k := range n.Children() {
			c.Kids = append(c.Kids, trimmed(k, depth-1))
		}
	}
	return &c
}

func (s *Server) listFixes(a args) (any, error) {
	t, _, _, err := s.treeOf(a)
	if err != nil {
		return nil, err
	}
	n, err := a.limit(len(t.Nodes))
	if err != nil {
		return nil, err
	}
	out := *t
	out.Nodes = nil
	for _, x := range t.Nodes[:n] {
		out.Nodes = append(out.Nodes, trimmed(x, 1))
	}
	return out, nil
}

func (s *Server) getFix(a args) (any, error) {
	t, hosts, v, err := s.treeOf(a)
	if err != nil {
		return nil, err
	}
	n := t.Find(a.str("id"))
	if n == nil {
		return nil, errors.New("unknown id: take one from list_fixes (with the same by and filters)")
	}
	d := tree.Describe(n, hosts, v, mcpToday())
	d.Node = trimmed(n, 2)
	return d, nil
}

// listServers: every server of the env with the columns of one lens, as the server view shows them (/api/lens).
func (s *Server) listServers(a args) (any, error) {
	l := lens.Get(a.str("lens"))
	if l == nil {
		return nil, errors.New("unknown lens: " + strings.Join(lens.IDs(), ", "))
	}
	org, env, v, err := s.view(a)
	if err != nil {
		return nil, err
	}
	set, err := s.store.Findings(org.ID, env)
	if err != nil {
		return nil, err
	}
	o := tree.Opts{By: tree.ByHost, All: true, Inventory: tree.Servers(org, env, v, set.Inventory()), Today: mcpToday()}
	res := lens.Build(l, lens.Input{Servers: tree.BuildSet(set, tree.Hosts(v.Facts), o), View: v, Findings: set.Select(lens.Reads),
		Lang: a.str("lang")})
	if lv := a.str("level"); lv != "" { // only rows with a cell of this level (bad: what needs attention)
		rows := []lens.Row{}
		for _, r := range res.Rows {
			for _, c := range r.Cells {
				if c.Level == lv {
					rows = append(rows, r)
					break
				}
			}
		}
		res.Rows = rows
	}
	return res, nil
}
