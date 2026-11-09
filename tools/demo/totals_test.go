package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/mcp"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/server"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// what every interface says about an environment: fixes to apply (per priority and with nothing to install yet),
// unique CVEs and hosts with something to do
type said struct {
	Fixes, P1, P2, P3, P4, NoFix, CVEs, Hosts int
}

func ofTotals(t report.Totals) said {
	return said{t.Fixes, t.P1, t.P2, t.P3, t.P4, t.NoFix, t.CVEs, t.Hosts}
}

// TestTotalsAgree: the same demo data yields the same numbers through every path a person or an agent reads them
// from: the scan's last line and summary.md (run.json's totals), /api/env's run list, /api/tree (the ToDo header
// and priority chips), MCP get_summary and list_fixes — for the last run and for the current state.
func TestTotalsAgree(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	home := filepath.Join(t.TempDir(), "demo")
	if err := generate(home, time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC), 6); err != nil {
		t.Fatal(err)
	}
	paths := config.PathsAt(home)
	env := filepath.Join(home, "reports", "acme", "production")
	runs, _ := filepath.Glob(filepath.Join(env, "2026-*"))
	last := runs[len(runs)-1]

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
	type treeJSON struct {
		Fixes, CVEs, Hosts int
		NoFix              int `json:"no_fix"`
		Counts             map[string]int
		Nodes              []json.RawMessage
	}
	ofTree := func(tr treeJSON) said {
		return said{tr.Fixes, tr.Counts["P1"], tr.Counts["P2"], tr.Counts["P3"], tr.Counts["P4"], tr.NoFix, tr.CVEs, tr.Hosts}
	}

	// the last run
	fs, err := report.LoadFindings(last)
	if err != nil {
		t.Fatal(err)
	}
	want := report.TotalsOf(fs)
	if want.Fixes == 0 || want.CVEs == 0 || want.NoFix == 0 || want.Fixes == want.Findings {
		t.Fatalf("demo totals %+v", want)
	}
	meta, err := report.LoadMeta(last)
	if err != nil || meta.Totals == nil || *meta.Totals != want {
		t.Fatalf("run.json totals %+v, want %+v (%v)", meta.Totals, want, err)
	}
	sum, _ := os.ReadFile(filepath.Join(last, "summary.md"))
	if !strings.Contains(string(sum), want.Line()) { // the scan prints the same line
		t.Errorf("summary.md lacks %q", want.Line())
	}
	var envResp struct {
		Runs []struct {
			RunID  string        `json:"run_id"`
			Totals report.Totals `json:"totals"`
		}
	}
	get("/api/env?org=acme&env=production", &envResp)
	if r := envResp.Runs[len(envResp.Runs)-1]; r.RunID != filepath.Base(last) || r.Totals != want {
		t.Errorf("/api/env: %s %+v, want %+v", r.RunID, r.Totals, want)
	}
	var tr treeJSON
	get("/api/tree?org=acme&env=production&run="+filepath.Base(last), &tr)
	if got := ofTree(tr); got != ofTotals(want) {
		t.Errorf("/api/tree of the run: %+v, want %+v", got, ofTotals(want))
	}
	if len(tr.Nodes) != want.Fixes {
		t.Errorf("/api/tree: %d top rows, %d fixes", len(tr.Nodes), want.Fixes)
	}

	// the current state
	cur, err := report.LoadFindings(filepath.Join(env, report.Current))
	if err != nil {
		t.Fatal(err)
	}
	want = report.TotalsOf(cur)
	cmeta, _ := report.LoadMeta(filepath.Join(env, report.Current))
	if cmeta.Totals == nil || *cmeta.Totals != want {
		t.Errorf("current/run.json totals %+v, want %+v", cmeta.Totals, want)
	}
	get("/api/tree?org=acme&env=production&run=current", &tr)
	if got := ofTree(tr); got != ofTotals(want) {
		t.Errorf("/api/tree: %+v, want %+v", got, ofTotals(want))
	}

	ms := mcp.NewServer(paths, "test")
	ms.Log = &bytes.Buffer{}
	call := func(name string, args map[string]any, v any) {
		t.Helper()
		req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args}})
		var out bytes.Buffer
		if err := ms.Serve(context.Background(), bytes.NewReader(append(req, '\n')), &out); err != nil {
			t.Fatal(err)
		}
		var resp struct {
			Result struct {
				Content []struct{ Text string }
				IsError bool
			}
		}
		if err := json.Unmarshal(out.Bytes(), &resp); err != nil || resp.Result.IsError || len(resp.Result.Content) == 0 {
			t.Fatalf("%s: %s", name, out.String())
		}
		if err := json.Unmarshal([]byte(resp.Result.Content[0].Text), v); err != nil {
			t.Fatal(err)
		}
	}
	var summary struct {
		Totals struct {
			Fixes, P1, P2, P3, P4, CVEs, Hosts int
			NoFix                              int `json:"no_fix"`
		}
		Hosts map[string]map[string]any
	}
	call("get_summary", map[string]any{"org": "acme", "env": "production"}, &summary)
	s := summary.Totals
	if got := (said{s.Fixes, s.P1, s.P2, s.P3, s.P4, s.NoFix, s.CVEs, s.Hosts}); got != ofTotals(want) {
		t.Errorf("get_summary: %+v, want %+v", got, ofTotals(want))
	}
	var lf treeJSON
	call("list_fixes", map[string]any{"org": "acme", "env": "production", "limit": 1}, &lf)
	if got := ofTree(lf); got != ofTotals(want) {
		t.Errorf("list_fixes: %+v, want %+v", got, ofTotals(want))
	}

	// the server view: every host, per host the same numbers as get_summary's hosts
	var sv struct {
		Servers map[string]int
		Nodes   []tree.Node
	}
	get("/api/tree?org=acme&env=production&run=current&by=host&all=1&f=kev", &sv)
	byName := map[string]tree.Node{}
	for _, n := range sv.Nodes {
		byName[n.Label] = n
	}
	for name, st := range map[string]string{cleanHost: tree.StateClean, partialHost: tree.StatePartial, downHost: tree.StateFailed,
		newHost: tree.StateNotScanned, "web-01": tree.StateTodo} {
		n, ok := byName[name]
		if !ok || n.State != st {
			t.Errorf("%s: state %q, want %q", name, n.State, st)
		}
		if st != tree.StateTodo && st != tree.StateClean && n.Problem == "" {
			t.Errorf("%s: no problem text", name)
		}
		if hs, ok := summary.Hosts[name]; ok && hs["fixes"] != nil && int(hs["fixes"].(float64)) != n.Fixes {
			t.Errorf("%s: %d fixes, get_summary %v", name, n.Fixes, hs["fixes"])
		}
	}
	if p := byName[partialHost].Problem; !strings.Contains(p, "/etc/shadow") || !strings.Contains(p, "no passwordless sudo") {
		t.Errorf("partial: %q", p)
	}
	if p := byName[downHost].Problem; !strings.Contains(p, "connection refused") || !strings.Contains(p, "nothing listens") {
		t.Errorf("failed: %q", p)
	}
	if byName[newHost].LastScan != "" || byName[cleanHost].LastScan == "" {
		t.Errorf("last scan: new %q, clean %q", byName[newHost].LastScan, byName[cleanHost].LastScan)
	}
	if l := sv.Nodes[len(sv.Nodes)-1]; l.State != tree.StateClean {
		t.Errorf("last row %s is %s, want a clean host", l.Label, l.State)
	}
	if len(sv.Nodes) != 120 || sv.Servers[tree.StateClean] == 0 { // and the k8s cluster, whose findings are its own row
		t.Errorf("%d host rows (want 119 production hosts of the org file + the k8s cluster), %v", len(sv.Nodes), sv.Servers)
	}
	var mv struct{ Nodes []tree.Node }
	call("list_fixes", map[string]any{"org": "acme", "env": "production", "by": "host", "all": true, "limit": 500}, &mv)
	if len(mv.Nodes) != len(sv.Nodes) || mv.Nodes[0].Label != sv.Nodes[0].Label {
		t.Errorf("list_fixes all: %d rows, the page %d", len(mv.Nodes), len(sv.Nodes))
	}
}
