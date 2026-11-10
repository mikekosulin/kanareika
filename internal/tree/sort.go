package tree

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// sortKeys: the columns rows sort by, each in its natural direction: the most first (CVEs, EPSS, hosts, fixes, the
// latest scan), the earliest due date first (none last), names A to Z, the most urgent priority first.
var sortKeys = map[string]func(a, b *Node) int{
	"pri":     func(a, b *Node) int { return cmp.Compare(sevRankP(a.Priority), sevRankP(b.Priority)) },
	"cve":     func(a, b *Node) int { return cmp.Compare(b.CVEs, a.CVEs) },
	"epss":    func(a, b *Node) int { return cmp.Compare(b.EPSS, a.EPSS) },
	"hosts":   func(a, b *Node) int { return cmp.Compare(b.Hosts, a.Hosts) },
	"fixes":   func(a, b *Node) int { return cmp.Compare(b.Fixes, a.Fixes) },
	"scanned": func(a, b *Node) int { return strings.Compare(b.LastScan, a.LastScan) },
	"due":     func(a, b *Node) int { return lastEmpty(a.Due, b.Due) },
	"name":    func(a, b *Node) int { return strings.Compare(strings.ToLower(a.Label), strings.ToLower(b.Label)) },
}

// sevRankP: P1 first, no priority last.
func sevRankP(p string) int {
	if len(p) == 2 && p[0] == 'P' {
		return int(p[1] - '0')
	}
	return 9
}

func lastEmpty(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	return strings.Compare(a, b)
}

// Sorter: the order of a sort key ("cve", "-cve" reversed); "" keeps the tree's own order (nil).
func Sorter(by string) (func(a, b *Node) int, error) {
	if by == "" {
		return nil, nil
	}
	key, rev := strings.CutPrefix(by, "-")
	f := sortKeys[key]
	if f == nil {
		return nil, fmt.Errorf("unknown sort %q: one of pri, cve, epss, hosts, fixes, scanned, due, name (- before it reverses)", by)
	}
	if rev {
		return func(a, b *Node) int { return f(b, a) }, nil
	}
	return f, nil
}

// Sorted: t with its top rows in the order of by (ties keep the tree's order); t is not changed. nil by: t.
func (t *Tree) Sorted(by func(a, b *Node) int) *Tree {
	if by == nil {
		return t
	}
	c := *t
	c.Nodes = slices.Clone(t.Nodes)
	slices.SortStableFunc(c.Nodes, by)
	return &c
}

// SortAll orders ns and the kids under them by by, in place: for nodes copied for an answer (Shallow, Full).
// Headings inside a node keep it as it is: its kids come in parts.
func SortAll(ns []*Node, by func(a, b *Node) int) {
	if by == nil || slices.ContainsFunc(ns, func(n *Node) bool { return n.Kind == KindSection }) {
		return
	}
	slices.SortStableFunc(ns, by)
	for _, n := range ns {
		SortAll(n.Kids, by)
	}
}
