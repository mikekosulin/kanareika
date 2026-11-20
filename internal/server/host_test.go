package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// TestHostFixes: /api/host lists one server's fixes, the most urgent first, with ids /api/node (by host) describes;
// a server with nothing open has none, and the host is required.
func TestHostFixes(t *testing.T) {
	p, _ := fixtureHome(t)
	_, h := newTest(t, Options{Paths: p})
	base := "/api/host?org=acme&env=production&run=current"
	var a hostFixes
	r := do(h, "GET", base+"&host=web-01", nil, nil)
	must(t, json.Unmarshal([]byte(r.body), &a))
	if r.code != 200 || a.ID != "g:web/h:web-01" || a.Node == nil || a.Node.Label != "web-01" || len(a.Fixes) == 0 {
		t.Fatal(r.code, r.body[:min(400, len(r.body))])
	}
	for i, f := range a.Fixes {
		if !strings.HasPrefix(f.ID, a.ID+"/") {
			t.Errorf("fix %s is not under %s", f.ID, a.ID)
		}
		if i > 0 && f.Priority < a.Fixes[i-1].Priority {
			t.Errorf("%s (%s) after %s (%s)", f.ID, f.Priority, a.Fixes[i-1].ID, a.Fixes[i-1].Priority)
		}
	}
	var d tree.Detail
	r = do(h, "GET", "/api/node?org=acme&env=production&run=current&by=host&id="+a.Fixes[0].ID, nil, nil)
	if r.code != 200 || json.Unmarshal([]byte(r.body), &d) != nil || d.Node.ID != a.Fixes[0].ID {
		t.Fatal(r.code, r.body)
	}
	for _, w := range d.Where {
		if !slices.Equal(w.Hosts, []string{"web-01"}) {
			t.Errorf("a server's fix is about that server only: %v", w.Hosts)
		}
	}
	var dd hostFixes
	r = do(h, "GET", base+"&host=web-01&detail=1", nil, nil)
	must(t, json.Unmarshal([]byte(r.body), &dd))
	if len(dd.Details) != len(dd.Fixes) || dd.Details[0].Node.ID != dd.Fixes[0].ID || len(dd.Details[0].CVEs) != len(d.CVEs) {
		t.Fatalf("details: %d for %d fixes", len(dd.Details), len(dd.Fixes))
	}
	if len(a.Details) != 0 {
		t.Fatal("details without ?detail=1")
	}
	if r := do(h, "GET", base+"&host=nope", nil, nil); r.code != 200 || r.body != `{"id":"","fixes":[]}`+"\n" && r.body != `{"id":"","fixes":[]}` {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "GET", base, nil, nil); r.code != 400 {
		t.Fatal(r.code, r.body)
	}
}

// TestHostTask: the agent task from a server's page (?host=) covers that server only, even for an image update that
// runs on other hosts too.
func TestHostTask(t *testing.T) {
	p, _ := fixtureHome(t)
	var seen []report.Action
	_, h := newTest(t, Options{Paths: p, Prompt: func(_ *config.Org, _ string, v *report.View, ids []string, _ string) string {
		for _, a := range v.Actions {
			if slices.Contains(ids, a.ID) {
				seen = append(seen, a)
			}
		}
		return "task"
	}})
	q := "/api/prompt?org=acme&env=production&run=current&by=host&nodes=g:web"
	if r := do(h, "GET", q, nil, nil); r.code != 200 {
		t.Fatal(r.code, r.body)
	}
	wide := false
	for _, a := range seen {
		wide = wide || len(a.Hosts) > 1 || !slices.Contains(a.Hosts, "web-01")
	}
	if !wide {
		t.Fatal("the fixture should have actions beyond web-01 for this test to mean anything")
	}
	seen = nil
	if r := do(h, "GET", q+"&host=web-01", nil, nil); r.code != 200 {
		t.Fatal(r.code, r.body)
	}
	if len(seen) == 0 {
		t.Fatal("no actions for web-01")
	}
	for _, a := range seen {
		if !slices.Equal(a.Hosts, []string{"web-01"}) {
			t.Errorf("action %s: hosts %v", a.ID, a.Hosts)
		}
	}
}

// TestHostHistory: a server's runs newest first, with what appeared and went on it (not on other hosts), a run
// that could not reach it marked failed, and a partial run that left it out skipped.
func TestHostHistory(t *testing.T) {
	p, env := fixtureHome(t)
	run := func(id string, meta map[string]any, newRows, gone []map[string]any) {
		dir := filepath.Join(env, id)
		must(t, os.MkdirAll(dir, 0o755))
		meta["run_id"], meta["started"], meta["finished"] = id, id, id+"Z"
		b, _ := json.Marshal(meta)
		must(t, os.WriteFile(filepath.Join(dir, "run.json"), b, 0o644))
		v, _ := json.Marshal(map[string]any{"version": report.ViewVersion, "new": map[string]any{"total": len(newRows), "rows": newRows},
			"resolved": map[string]any{"total": len(gone), "rows": gone}})
		must(t, os.WriteFile(filepath.Join(dir, "view.json"), v, 0o644))
	}
	row := func(host, pkg string) map[string]any {
		return map[string]any{"host": host, "target": "os", "pkg": pkg, "ids": []string{"CVE-0000-0001"}, "priority": "P2", "count": 1}
	}
	all := map[string]any{"groups": []string{}, "hosts": []string{}, "modules": []string{}}
	run("2026-11-03_100000", map[string]any{"selection": all},
		[]map[string]any{row("web-01", "openssl"), row("app-01", "curl")}, []map[string]any{row("web-01", "sudo")})
	run("2026-11-03_110000", map[string]any{"selection": map[string]any{"hosts": []string{"app-01"}}},
		[]map[string]any{row("app-01", "zlib")}, nil)
	run("2026-11-03_120000", map[string]any{"selection": map[string]any{"groups": []string{"front"}}, "hosts_failed": map[string]any{"web-01": "timeout"}}, nil, nil)
	_, h := newTest(t, Options{Paths: p})
	var a struct{ Runs []hostRun }
	r := do(h, "GET", "/api/host/history?org=acme&env=production&host=web-01", nil, nil)
	must(t, json.Unmarshal([]byte(r.body), &a))
	if r.code != 200 || len(a.Runs) < 2 {
		t.Fatal(r.code, r.body)
	}
	got := func(i int) string {
		x := a.Runs[i]
		pk := func(cs []hostChange) (s []string) {
			for _, c := range cs {
				s = append(s, c.Host+":"+c.Pkg)
			}
			return
		}
		return fmt.Sprintf("%s %s +%v -%v", x.RunID, x.State, pk(x.New), pk(x.Resolved))
	}
	for i, want := range []string{"2026-11-03_120000 failed +[] -[]", "2026-11-03_100000 ok +[web-01:openssl] -[web-01:sudo]"} {
		if g := got(i); g != want {
			t.Errorf("run %d: %s, want %s", i, g, want)
		}
	}
	for _, x := range a.Runs {
		if x.RunID == "2026-11-03_110000" {
			t.Error("a partial run of app-01 alone listed for web-01")
		}
	}
	if r := do(h, "GET", "/api/host/history?org=acme&env=production", nil, nil); r.code != 400 {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "GET", "/api/host/history?org=nope&env=production&host=web-01", nil, nil); r.code < 400 {
		t.Fatal(r.code, r.body)
	}
}
