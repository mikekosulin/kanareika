package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/lens"
	"github.com/mikekosulin/kanareika/internal/mcp"
	"github.com/mikekosulin/kanareika/internal/server"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// TestLensRows: every lens over the demo: one row per host in the order and with the states of the server view;
// failed and never scanned hosts have no cells; the partly checked host says what was not checked; MCP
// list_servers answers the same rows.
func TestLensRows(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	home := filepath.Join(t.TempDir(), "demo")
	if err := generate(home, time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC), 6); err != nil {
		t.Fatal(err)
	}
	paths := config.PathsAt(home)
	srv, err := server.New(server.Options{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	get := func(path string, v any) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}
	var sv struct{ Nodes []tree.Node }
	get("/api/tree?org=acme&env=production&run=current&by=host&all=1", &sv)
	byLens := map[string]map[string]lens.Row{}
	for _, id := range lens.IDs() {
		var res lens.Result
		get("/api/lens?org=acme&env=production&run=current&id="+id, &res)
		if res.Lens.ID != id || len(res.Lenses) != len(lens.All) || len(res.Lens.Columns) == 0 || res.Lens.Columns[0].Title == "" {
			t.Fatalf("%s: %+v", id, res.Lens)
		}
		if len(res.Rows) != len(sv.Nodes) {
			t.Fatalf("%s: %d rows, server view %d", id, len(res.Rows), len(sv.Nodes))
		}
		rows := map[string]lens.Row{}
		for i, r := range res.Rows {
			if r.Host != sv.Nodes[i].Label || r.State != sv.Nodes[i].State {
				t.Fatalf("%s: row %d %s/%s, server view %s/%s", id, i, r.Host, r.State, sv.Nodes[i].Label, sv.Nodes[i].State)
			}
			if r.State == tree.StateTodo || r.State == tree.StateClean || r.State == tree.StatePartial {
				for _, c := range res.Lens.Columns {
					if _, ok := r.Cells[c.Key]; !ok && r.Host[0] != 'k' { // the k8s cluster row has no host data
						t.Errorf("%s %s: no cell %s", id, r.Host, c.Key)
					}
				}
			}
			rows[r.Host] = r
		}
		for _, name := range []string{downHost, newHost} {
			if r := rows[name]; len(r.Cells) != 0 || r.Problem == "" {
				t.Errorf("%s %s: %+v", id, name, r)
			}
		}
		byLens[id] = rows
	}
	if c := byLens["priorities"][cleanHost]; c.State != tree.StateClean || c.Cells["fixes"].V != float64(0) || c.Cells["P1"].Level != lens.OK {
		t.Errorf("clean: %+v", c)
	}
	if c := byLens["priorities"]["web-01"].Cells; c["internet"].V != true || c["os"].S != "Debian 12" || c["fixes"].V == float64(0) {
		t.Errorf("web-01: %+v", c)
	}
	p := byLens["logins"][partialHost]
	if p.State != tree.StatePartial || p.Cells["pw_users"].S != lens.ResultUnknown || p.Cells["failed_24h"].Note != "not checked (needs root)" ||
		p.Cells["keys"].S != "1" {
		t.Errorf("partial: %+v", p)
	}
	if c := byLens["logins"]["web-01"].Cells["password"]; c.Level != lens.Bad {
		t.Errorf("web-01 password: %+v", c)
	}
	if c := byLens["network"]["web-01"].Cells; c["firewall"].Level != lens.Bad || c["open_ports"].S != "22 80 443 6379" {
		t.Errorf("web-01 network: %+v", c)
	}
	if c := byLens["health"]["web-01"].Cells["disk"]; c.Level != lens.OK || c.V == nil {
		t.Errorf("web-01 disk: %+v", c)
	}
	var ru lens.Result
	get("/api/lens?org=acme&env=production&run=current&id=logins&lang=ru", &ru)
	if ru.Lens.Title != "Входы" {
		t.Errorf("ru: %q", ru.Lens.Title)
	}

	ms := mcp.NewServer(paths, "test")
	ms.Log = &bytes.Buffer{}
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
		"name": "list_servers", "arguments": map[string]any{"org": "acme", "env": "production", "lens": "logins", "level": "bad"}}})
	var out bytes.Buffer
	if err := ms.Serve(context.Background(), bytes.NewReader(append(req, '\n')), &out); err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Result struct{ Content []struct{ Text string } }
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil || len(resp.Result.Content) == 0 {
		t.Fatal(out.String())
	}
	var bad lens.Result
	if err := json.Unmarshal([]byte(resp.Result.Content[0].Text), &bad); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range bad.Rows {
		found = found || r.Host == "web-01"
		if byLens["logins"][r.Host].State != r.State {
			t.Errorf("list_servers %s: %s", r.Host, r.State)
		}
	}
	if !found || len(bad.Rows) == 0 || len(bad.Rows) >= len(sv.Nodes) {
		t.Errorf("list_servers level=bad: %d rows, web-01 %v", len(bad.Rows), found)
	}
}
