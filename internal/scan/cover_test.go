package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
)

func readStatus(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "status.json"))
	must(t, err)
	var st map[string]any
	must(t, json.Unmarshal(b, &st))
	return st
}

func TestProgress(t *testing.T) {
	old := Heartbeat
	Heartbeat = time.Hour
	t.Cleanup(func() { Heartbeat = old })

	if _, err := NewProgress(filepath.Join(t.TempDir(), "missing"), "t1", "default", "r", nil, nil); err == nil {
		t.Fatal("run dir that does not exist accepted")
	}

	dir := t.TempDir()
	p, err := NewProgress(dir, "t1", "default", "r1", []string{"web-01", "web-02", "web-03"}, []string{"k8s"})
	must(t, err)
	for i := 0; i < 250; i++ {
		p.Line("[12:00:00] web-01: line " + strings.Repeat("x", i%3))
	}
	p.Line("[12:00:00] web-02: " + strings.Repeat("é", 300))
	p.Host("db-99", HostUpdate{State: "ok"}) // unknown: ignored
	p.Host("web-01", HostUpdate{State: "ok", Steps: 4, Step: 2, Module: ptr("health"), Errors: ptr(1)})
	p.Host("web-03", HostUpdate{State: "running", Module: ptr("access")})
	p.OrgModule("k8s", "done")
	if len(p.tail) != 200 {
		t.Fatalf("tail kept %d lines", len(p.tail))
	}
	st := readStatus(t, dir)
	if n := len(st["log_tail"].([]any)); n != 60 {
		t.Fatalf("status log tail %d lines", n)
	}
	h2 := st["hosts"].(map[string]any)["web-02"].(map[string]any)
	if r := []rune(h2["last"].(string)); len(r) != 200 || r[0] != 'é' {
		t.Fatalf("last not cut to 200 runes: %d", len(r))
	}
	if _, ok := st["hosts"].(map[string]any)["db-99"]; ok {
		t.Fatal("unknown host added")
	}

	// a value that cannot be encoded: status.json keeps its last good content
	p.Finish("done", map[string]any{"bad": make(chan int)})
	st = readStatus(t, dir)
	if st["state"] != "running" {
		t.Fatalf("unencodable status written: %v", st["state"])
	}
	h1 := p.hosts["web-01"]
	if h1.Step != 4 || h1.Module != nil || h1.State != "ok" || p.hosts["web-03"].State != "skipped" || p.hosts["web-02"].State != "skipped" {
		t.Fatalf("finish: %+v %+v", h1, p.hosts["web-03"])
	}
}

func TestPreflightWindowDefaultTZ(t *testing.T) {
	e := newEnv(t)
	o := e.org(map[string]any{"document": "t", "signed": "2026-01-01", "valid_until": "2099-01-01",
		"window": map[string]any{"from": "01:00", "to": "02:00"}}, e.here())
	noon := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	got := Preflight(o, Plan{}, false, noon)
	if len(got) != 1 || !strings.Contains(got[0], "outside scan window 01:00-02:00 UTC") {
		t.Fatal(got)
	}
	if got := Preflight(o, Plan{}, true, noon); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestDryRunJumpAndNoModules(t *testing.T) {
	e := newEnv(t)
	o := e.orgWith(nil, map[string]any{"web-01": map[string]any{"address": "192.0.2.10", "jump": "bastion"}}, func(doc map[string]any) {
		doc["access"].(map[string]any)["jumps"] = map[string]any{"bastion": map[string]any{"address": "198.51.100.1"}}
	})
	rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{DryRun: true, IgnoreWindow: true, Modules: []string{"k8s"}})
	if rc != 0 || !strings.Contains(e.out.String(), "via bastion: -") {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
}

func TestNoKey(t *testing.T) {
	e := newEnv(t)
	o := e.org(nil, e.here())
	must(t, os.Remove(filepath.Join(e.paths.Secrets, "t1", "key")))
	rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true})
	if rc != 1 || !strings.Contains(e.out.String(), "SSH key not found") || !strings.Contains(e.out.String(), "refusing to scan") {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
}

// TestFactsFallbacks: RHEL 6 has only redhat-release; a module that is not
// implemented is a module error; an org module without an implementation is skipped; the feeds date is stored.
func TestFactsFallbacks(t *testing.T) {
	e := newEnv(t)
	ran := fakeModules(t)
	HostModules["health"] = nil
	oldOrg := OrgModules
	OrgModules = map[string]OrgFunc{"network_external": nil}
	t.Cleanup(func() { OrgModules = oldOrg })
	consent := map[string]any{"document": "t", "signed": "2026-01-01", "valid_until": "2099-01-01", "external_scan": true}
	o := e.orgWith(consent, e.here(), func(doc map[string]any) {
		doc["checks"] = map[string]any{"network_external": true}
		doc["external"] = []any{"203.0.113.10"}
	})

	feeds := os.Getenv("KANAREIKA_FEEDS_DIR")
	must(t, os.MkdirAll(feeds, 0o755))
	must(t, os.WriteFile(filepath.Join(feeds, "kev.json"), []byte(`["CVE-2024-0001"]`), 0o644))
	must(t, os.WriteFile(filepath.Join(feeds, "epss.json"), []byte(`{}`), 0o644))
	must(t, os.WriteFile(filepath.Join(feeds, "updated"), []byte("2026-11-01T00:00:00+00:00\n"), 0o644))

	e.target.mu.Lock()
	e.target.facts = "@@Linux 2.6.32 x86_64\n@@old-01\n@@CentOS release 6.10 (Final)\n"
	e.target.mu.Unlock()
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 0 {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	if v, _ := ran.Load("web-01/os_packages"); v != "centos" {
		t.Fatalf("redhat-release fallback: ID %v\n%s", v, e.out)
	}
	m, st := lastRun(t, report.EnvDir(e.paths, "t1", config.DefaultEnv))
	if m.FeedsUpdated == nil || *m.FeedsUpdated != "2026-11-01T00:00:00+00:00" {
		t.Fatalf("feeds_updated: %v", m.FeedsUpdated)
	}
	if errs, _ := m.ModuleErrors.Get("web-01"); len(errs) != 1 || errs[0] != "health: not implemented yet" {
		t.Fatalf("module errors: %v", errs)
	}
	if st["org_modules"].(map[string]any)["network_external"] != "pending" {
		t.Fatalf("org module without implementation ran: %v", st["org_modules"])
	}
}

// TestFactsUnknownOS: a host with neither os-release nor redhat-release shows "?".
func TestFactsUnknownOS(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	o := e.org(nil, e.here())
	e.target.mu.Lock()
	e.target.facts = "@@Linux 6.1.0 x86_64\n@@bare-01\n@@"
	e.target.mu.Unlock()
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 0 {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	if !strings.Contains(e.out.String(), "web-01: ? (bare-01)") {
		t.Fatal(e.out)
	}
}

// TestInterrupted: Ctrl+C during a run that then cannot finish marks it interrupted.
func TestInterrupted(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for name := range HostModules {
		HostModules[name] = func(*check.Ctx, config.Host, map[string]any, string, check.Facts) ([]finding.Finding, error) {
			must(t, os.MkdirAll(e.paths.Policy, 0o755))
			must(t, os.WriteFile(filepath.Join(e.paths.Policy, "priority.yml"), []byte("rules: ["), 0o644))
			cancel()
			return nil, nil
		}
	}
	o := e.org(nil, e.here())
	if rc := e.scanner().Org(ctx, o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 {
		t.Fatalf("rc 0\n%s", e.out)
	}
	runs, _ := filepath.Glob(filepath.Join(report.EnvDir(e.paths, "t1", config.DefaultEnv), "20*"))
	if len(runs) != 1 {
		t.Fatal(runs)
	}
	if st := readStatus(t, runs[0]); st["state"] != "interrupted" || st["error"] != "aborted" {
		t.Fatalf("status: %v", st)
	}
}

// TestSaveRunFails: run.json cannot be written; the run is reported failed.
func TestSaveRunFails(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	for name := range HostModules {
		HostModules[name] = func(ctx *check.Ctx, _ config.Host, _ map[string]any, _ string, _ check.Facts) ([]finding.Finding, error) {
			// a non-empty directory where findings.json.gz goes: the atomic rename onto it fails
			return nil, os.MkdirAll(filepath.Join(ctx.RunDir, "findings.json.gz", "x"), 0o755)
		}
	}
	o := e.org(nil, e.here())
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 {
		t.Fatalf("rc 0\n%s", e.out)
	}
	if !strings.Contains(e.out.String(), "findings.json.gz") || strings.Contains(e.out.String(), "done: ") {
		t.Fatal(e.out)
	}
	runs, _ := filepath.Glob(filepath.Join(report.EnvDir(e.paths, "t1", config.DefaultEnv), "20*"))
	if st := readStatus(t, runs[0]); st["state"] != "failed" {
		t.Fatalf("status: %v", st["state"])
	}
}

// TestCurrentAndPruneErrors: a broken run directory in the env does not fail the finished run; both the merge
// into the current state and the pruning only log their errors.
func TestCurrentAndPruneErrors(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	o := e.org(nil, e.here())
	envDir := report.EnvDir(e.paths, "t1", config.DefaultEnv)
	broken := filepath.Join(envDir, "2999-01-01_000000") // later than this run: not its previous run
	must(t, os.MkdirAll(broken, 0o755))
	must(t, os.WriteFile(filepath.Join(broken, "run.json"), []byte("{"), 0o644))
	rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true})
	if rc != 0 {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	for _, want := range []string{"current state: ", "prune: ", "done: "} {
		if !strings.Contains(e.out.String(), want) {
			t.Fatalf("%q not in\n%s", want, e.out)
		}
	}
}

// TestRunDirErrors: the run directory or its log cannot be created.
func TestRunDirErrors(t *testing.T) {
	e := newEnv(t)
	o := e.org(nil, e.here())
	sel, err := SelectHosts(o, config.DefaultEnv, nil, nil)
	must(t, err)
	p := MakePlan(o, sel, nil, true)

	file := filepath.Join(t.TempDir(), "env")
	must(t, os.WriteFile(file, nil, 0o644))
	if rc := e.scanner().run(context.Background(), o, config.DefaultEnv, sel, Options{}, p, nil, file); rc != 1 ||
		!strings.Contains(e.out.String(), errNotDir) {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}

	// run.log is a directory in every run directory this run could get
	e.out.Reset()
	envDir := t.TempDir()
	start := time.Now().UTC()
	for i := -1; i < 30; i++ {
		must(t, os.MkdirAll(filepath.Join(envDir, start.Add(time.Duration(i)*time.Second).Format("2006-01-02_150405"), "run.log"), 0o755))
	}
	if rc := e.scanner().run(context.Background(), o, config.DefaultEnv, sel, Options{}, p, nil, envDir); rc != 1 ||
		!strings.Contains(e.out.String(), "run.log") {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
}
