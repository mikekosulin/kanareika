package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestGetFix: a fix from list_fixes, by its id, comes with its details: why, where, its CVEs (the most urgent
// first, how many more), and its node two levels deep; an id list_fixes didn't give is an error that says where to
// take one.
func TestGetFix(t *testing.T) {
	s, _ := newTestServer(fixtureHome(t))
	prod := map[string]any{"org": "acme", "env": "production"}
	text, isErr := tcall(t, s, "list_fixes", prod)
	if isErr {
		t.Fatal(text)
	}
	var list struct{ Nodes []struct{ ID string } }
	if err := json.Unmarshal([]byte(text), &list); err != nil || len(list.Nodes) == 0 {
		t.Fatalf("%v %s", err, text)
	}
	id := list.Nodes[0].ID
	text, isErr = tcall(t, s, "get_fix", map[string]any{"org": "acme", "env": "production", "id": id})
	if isErr {
		t.Fatal(text)
	}
	var d struct {
		Node  struct{ ID string }
		Why   []any
		Where []any
		CVEs  []struct{ ID string } `json:"cves"`
		More  *int                  `json:"cves_more"`
	}
	if err := json.Unmarshal([]byte(text), &d); err != nil {
		t.Fatal(err)
	}
	if d.Node.ID != id || len(d.Why) == 0 || len(d.Where) == 0 || d.More == nil {
		t.Fatalf("%s", text)
	}
	wantToolError(t, s, "get_fix", map[string]any{"org": "acme", "env": "production", "id": "fix:nope"}, "take one from list_fixes")
	wantToolError(t, s, "get_fix", map[string]any{"org": "nope", "env": "production", "id": id}, "nope")
	wantToolError(t, s, "list_fixes", map[string]any{"org": "acme", "env": "production", "limit": "many"}, "invalid limit")
}

// TestListServersErrors: an unknown lens names the known ones; an unknown org is an error too.
func TestListServersErrors(t *testing.T) {
	s, _ := newTestServer(fixtureHome(t))
	wantToolError(t, s, "list_servers", map[string]any{"org": "acme", "env": "production", "lens": "nope"}, "unknown lens: ")
	wantToolError(t, s, "list_servers", map[string]any{"org": "nope", "env": "production", "lens": "priorities"}, "nope")
}

// TestFindingsDatabaseUnusable: when the findings database can't be opened, the tools that read findings say so
// instead of answering with nothing.
func TestFindingsDatabaseUnusable(t *testing.T) {
	home := fixtureHome(t)
	db := filepath.Join(home, "reports", "kanareika.db") // a directory with something in it: not a database, not removable
	writeFile(t, filepath.Join(db, "x"), "x")
	s, _ := newTestServer(home)
	prod := map[string]any{"org": "acme", "env": "production"}
	for _, tool := range []string{"list_fixes", "get_summary"} {
		if text, isErr := tcall(t, s, tool, prod); !isErr {
			t.Errorf("%s answered: %.80s", tool, text)
		}
	}
	if text, isErr := tcall(t, s, "list_servers", map[string]any{"org": "acme", "env": "production", "lens": "priorities"}); !isErr {
		t.Errorf("list_servers answered: %.80s", text)
	}
	_ = os.RemoveAll(db)
}

// TestListServers: every server of the env with a lens's columns; level keeps the rows with a cell of that level.
// list_fixes by host with all lists every server, scanned or not.
func TestListServers(t *testing.T) {
	s, _ := newTestServer(fixtureHome(t))
	type row struct {
		Cells map[string]struct{ Level string }
	}
	read := func(a map[string]any) []row {
		t.Helper()
		text, isErr := tcall(t, s, "list_servers", a)
		if isErr {
			t.Fatal(text)
		}
		var res struct{ Rows []row }
		if err := json.Unmarshal([]byte(text), &res); err != nil {
			t.Fatal(err)
		}
		return res.Rows
	}
	all := read(map[string]any{"org": "acme", "env": "production", "lens": "health"})
	bad := read(map[string]any{"org": "acme", "env": "production", "lens": "health", "level": "bad"})
	if len(all) == 0 || len(bad) > len(all) {
		t.Fatalf("%d rows, %d bad", len(all), len(bad))
	}
	for _, r := range bad {
		found := false
		for _, c := range r.Cells {
			found = found || c.Level == "bad"
		}
		if !found {
			t.Fatalf("a row without a bad cell: %+v", r)
		}
	}
	text, isErr := tcall(t, s, "list_fixes", map[string]any{"org": "acme", "env": "production", "by": "host", "all": true})
	var tr struct{ Nodes []struct{ Kind string } }
	if isErr || json.Unmarshal([]byte(text), &tr) != nil || len(tr.Nodes) == 0 {
		t.Fatalf("%v %.200s", isErr, text)
	}
}
