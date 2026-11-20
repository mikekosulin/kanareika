package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/tree"
)

// TestFacets: each filter's count is how many fixes the list would show with it on, the filters already on kept;
// priorities add up (P1 or P2), the rest narrow.
func TestFacets(t *testing.T) {
	p, _ := fixtureHome(t)
	old := today
	t.Cleanup(func() { today = old })
	today = func() string { return "2026-12-15" } // late enough for some findings to be overdue
	_, h := newTest(t, Options{Paths: p})
	get := func(f string) tree.Tree {
		t.Helper()
		var tr tree.Tree
		r := do(h, "GET", "/api/tree?org=acme&env=production&run=current&levels=0&f="+f, nil, nil)
		if r.code != http.StatusOK {
			t.Fatal(f, r.code, r.body)
		}
		must(t, json.Unmarshal([]byte(r.body), &tr))
		return tr
	}
	all := get("")
	if len(all.Facets) != len(tree.Facets) {
		t.Fatalf("facets %v", all.Facets)
	}
	nonzero := 0
	for _, k := range tree.Facets {
		if n := get(k).Fixes; all.Facets[k] != n {
			t.Errorf("facet %s: %d, the list with it on: %d", k, all.Facets[k], n)
		}
		if all.Facets[k] > 0 {
			nonzero++
		}
	}
	if nonzero < 4 {
		t.Fatalf("the fixture should exercise the facets: %v", all.Facets)
	}
	// with a filter on, another one's count is of both
	kev := get(tree.FKEV)
	for _, k := range []string{tree.FOverdue, tree.FReady, tree.FP1} {
		if n := get(tree.FKEV + "," + k).Fixes; kev.Facets[k] != n {
			t.Errorf("kev + %s: facet %d, list %d", k, kev.Facets[k], n)
		}
	}
	// priorities: any of them; with P1 on, P2's count is P2's own (choosing it adds its fixes)
	// a priority is the fix's own: its count is the list's count of that priority, and choosing it shows those fixes
	for _, k := range []string{tree.FP1, tree.FP2, tree.FP3, tree.FP4} {
		if all.Facets[k] != all.Counts[strings.ToUpper(k)] {
			t.Errorf("facet %s %d, the list's %s count %d", k, all.Facets[k], strings.ToUpper(k), all.Counts[strings.ToUpper(k)])
		}
	}
	p1, p2, both := get(tree.FP1), get(tree.FP2), get(tree.FP1+","+tree.FP2)
	if p1.Facets[tree.FP2] != p2.Fixes || both.Fixes != p1.Fixes+p2.Fixes {
		t.Fatalf("p1 %d, p2 %d, p1|p2 %d, p2 facet under p1 %d", p1.Fixes, p2.Fixes, both.Fixes, p1.Facets[tree.FP2])
	}
	for _, n := range p1.Nodes {
		if n.Priority != "P1" {
			t.Errorf("P1 filter shows %s %s", n.Priority, n.ID)
		}
	}
	// a priority with another filter: the fix's priority under that filter
	kp := get(tree.FKEV + "," + tree.FP1)
	if kev.Facets[tree.FP1] != kp.Fixes {
		t.Errorf("kev: P1 facet %d, kev+P1 list %d", kev.Facets[tree.FP1], kp.Fixes)
	}
}
