package mcp

import (
	"errors"
	"path/filepath"
	"time"

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
	fs, err := report.LoadFindings(filepath.Join(report.EnvDir(s.store.Paths, org.ID, env), report.Current))
	if err != nil {
		return nil, nil, nil, err
	}
	hosts := tree.Hosts(v.Facts)
	return tree.Build(fs, hosts, tree.Opts{By: a.str("by"), Filters: a.strs("filters"), Query: a.str("query"),
		Today: mcpToday()}), hosts, v, nil
}

// trimmed: a node without its subtree beyond depth (0: the node only).
func trimmed(n *tree.Node, depth int) *tree.Node {
	c := *n
	c.Kids = nil
	if depth > 0 {
		for _, k := range n.Kids {
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
