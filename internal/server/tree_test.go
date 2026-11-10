package server

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// TestTreeAPI: /api/tree groups a run's findings, /api/node explains one node, and the agent task can be asked
// for by tree nodes (the actions under them).
func TestTreeAPI(t *testing.T) {
	p, _ := fixtureHome(t)
	old := today
	t.Cleanup(func() { today = old })
	today = func() string { return "2026-11-03" }
	var asked []string
	_, h := newTest(t, Options{Paths: p, Prompt: func(_ *config.Org, _ string, _ *report.View, ids []string, _ string) string {
		asked = ids
		return "task"
	}})
	base := "/api/tree?org=acme&env=production&run=2026-11-02_100000"
	var tr tree.Tree
	for _, by := range []string{"", "&by=cve", "&by=host"} {
		r := do(h, "GET", base+by, nil, nil)
		if r.code != 200 {
			t.Fatal(by, r.code, r.body)
		}
		must(t, json.Unmarshal([]byte(r.body), &tr))
		if len(tr.Nodes) == 0 || tr.Fixes == 0 || strings.Contains(r.body, `"keys"`) {
			t.Fatalf("%s: %s", by, r.body[:min(300, len(r.body))])
		}
	}
	r := do(h, "GET", base, nil, nil)
	must(t, json.Unmarshal([]byte(r.body), &tr))
	id := tr.Nodes[0].ID
	r = do(h, "GET", "/api/node?org=acme&env=production&run=2026-11-02_100000&id="+id, nil, nil)
	var d tree.Detail
	if r.code != 200 || json.Unmarshal([]byte(r.body), &d) != nil || d.Node == nil || d.Node.ID != id || len(d.Where) == 0 {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "GET", "/api/node?org=acme&env=production&run=2026-11-02_100000&id=nope", nil, nil); r.code != 404 {
		t.Fatal(r.code)
	}
	if r := do(h, "GET", "/api/tree?org=acme&env=nowhere&run=2026-11-02_100000", nil, nil); r.code != 404 {
		t.Fatal(r.code)
	}
	r = do(h, "GET", "/api/prompt?org=acme&env=production&run=2026-11-02_100000&nodes="+id, nil, nil)
	if r.code != 200 || len(asked) == 0 || len(d.Actions) == 0 || asked[0] != d.Actions[0] {
		t.Fatal(r.code, r.body, asked, d.Actions)
	}
	// ?levels=0: the top rows, their kids counted; ?under=: one row's kids
	r = do(h, "GET", base+"&by=cve&levels=0", nil, nil)
	var sh, under tree.Tree // fresh: decoding into a used tree would keep its old kids
	must(t, json.Unmarshal([]byte(r.body), &sh))
	top := sh.Nodes[0]
	if r.code != 200 || top.Kids != nil || top.More == 0 {
		t.Fatal(r.code, r.body[:min(300, len(r.body))])
	}
	r = do(h, "GET", base+"&by=cve&levels=0&under="+url.QueryEscape(top.ID), nil, nil)
	must(t, json.Unmarshal([]byte(r.body), &under))
	if r.code != 200 || len(under.Nodes) != top.More {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "GET", base+"&under=nope", nil, nil); r.code != 404 {
		t.Fatal(r.code)
	}
	// filters narrow it down; nothing matching is an empty tree, not an error
	r = do(h, "GET", base+"&q=no-such-thing-anywhere", nil, nil)
	must(t, json.Unmarshal([]byte(r.body), &tr))
	if r.code != 200 || len(tr.Nodes) != 0 {
		t.Fatal(r.code, r.body)
	}
	// cached between requests, rebuilt for another run
	if r := do(h, "GET", "/api/tree?org=acme&env=production&run=current", nil, nil); r.code != 200 {
		t.Fatal(r.code, r.body)
	}
}

// TestTreePaging: ?offset=&limit= answers one page of the top rows (or of a node's kids) with how many there are;
// findings come from the store, and the server view follows edits of the org file within the same run.
func TestTreePaging(t *testing.T) {
	p, _ := fixtureHome(t)
	_, h := newTest(t, Options{Paths: p})
	base := "/api/tree?org=acme&env=production&run=2026-11-02_100000&by=cve&levels=0"
	var all, page tree.Tree
	must(t, json.Unmarshal([]byte(do(h, "GET", base, nil, nil).body), &all))
	if len(all.Nodes) < 3 || all.Rows != 0 {
		t.Fatalf("unpaged: %d rows, rows=%d", len(all.Nodes), all.Rows)
	}
	r := do(h, "GET", base+"&offset=1&limit=2", nil, nil)
	must(t, json.Unmarshal([]byte(r.body), &page))
	if r.code != 200 || page.Rows != len(all.Nodes) || len(page.Nodes) != 2 || page.Nodes[0].ID != all.Nodes[1].ID ||
		page.Fixes != all.Fixes {
		t.Fatal(r.code, r.body)
	}
	var past tree.Tree
	must(t, json.Unmarshal([]byte(do(h, "GET", base+"&offset=999&limit=10", nil, nil).body), &past))
	if len(past.Nodes) != 0 || past.Rows != len(all.Nodes) {
		t.Fatalf("past the end: %+v", past)
	}
	top := all.Nodes[0]
	var kids tree.Tree
	must(t, json.Unmarshal([]byte(do(h, "GET", base+"&limit=1&under="+url.QueryEscape(top.ID), nil, nil).body), &kids))
	if len(kids.Nodes) != 1 || kids.Rows != top.More {
		t.Fatalf("a node's kids, paged: %+v", kids)
	}
	var deep tree.Tree // no levels: every level under the node
	must(t, json.Unmarshal([]byte(do(h, "GET", strings.Replace(base, "&levels=0", "", 1)+"&under="+url.QueryEscape(top.ID), nil, nil).body), &deep))
	if len(deep.Nodes) != top.More || deep.Nodes[0].More != 0 {
		t.Fatalf("every level: %+v", deep.Nodes[0])
	}
	// the server view: cached, and rebuilt when the org file lists other hosts
	srv := "/api/tree?org=acme&env=production&run=current&by=host&all=1&levels=0"
	var before, after tree.Tree
	must(t, json.Unmarshal([]byte(do(h, "GET", srv, nil, nil).body), &before))
	org := filepath.Join(p.Orgs, "acme.yml")
	b, err := os.ReadFile(org)
	must(t, err)
	must(t, os.WriteFile(org, []byte(strings.Replace(string(b), "      dead-01:", "      new-01:\n        address: 192.0.2.250\n      dead-01:", 1)), 0o644))
	do(h, "GET", "/api/orgs", nil, nil) // the page reloads the org files
	must(t, json.Unmarshal([]byte(do(h, "GET", srv, nil, nil).body), &after))
	if len(after.Nodes) != len(before.Nodes)+1 || after.Servers[tree.StateNotScanned] != before.Servers[tree.StateNotScanned]+1 {
		t.Fatalf("a host added to the org file: %d -> %d rows", len(before.Nodes), len(after.Nodes))
	}
	if _, err := os.Stat(filepath.Join(p.Reports, "kanareika.db")); err != nil {
		t.Fatal("findings are read through the store:", err)
	}
}
