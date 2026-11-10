package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/report"
)

// withHealth: the fake modules, with health replaced by fn.
func withHealth(t *testing.T, fn check.Func) {
	t.Helper()
	fakeModules(t)
	HostModules["health"] = fn
}

// brokenPolicy: a priority.yml that does not parse.
func (e *env) brokenPolicy() {
	must(e.t, os.MkdirAll(e.paths.Policy, 0o755))
	must(e.t, os.WriteFile(filepath.Join(e.paths.Policy, "priority.yml"), []byte("rules: ["), 0o644))
}

// runFindings: the findings in the last run's file of host.
func runFindings(t *testing.T, envDir, host string) []finding.Finding {
	t.Helper()
	m, _ := lastRun(t, envDir)
	var got []finding.Finding
	must(t, report.EachFindingIn(filepath.Join(envDir, m.RunID, "hosts", host, "findings.json.gz"),
		func(f *finding.Finding) { got = append(got, *f) }))
	return got
}

func ids(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	slices.Sort(out)
	return out
}

func misconfig(h config.Host, id string) finding.Finding {
	return check.New(h, "health", finding.Misconfig, id, "HIGH", i18n.Plain(id), i18n.Plain(""), 0)
}

// The KEV / EPSS refresh before an online scan logs a failure or an update and goes on.
func TestScoresRefreshLogged(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	o := e.org(nil, e.here())
	for _, c := range []struct {
		got  bool
		err  error
		want string
	}{
		{false, errors.New("feeds unreachable"), "KEV / EPSS: not updated: feeds unreachable"},
		{true, nil, "KEV / EPSS: updated"},
	} {
		refreshScores = func(context.Context, *priority.Policy, time.Duration) (bool, error) { return c.got, c.err }
		e.out.Reset()
		if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 0 {
			t.Fatalf("rc %d\n%s", rc, e.out)
		}
		if !strings.Contains(e.out.String(), c.want) {
			t.Errorf("%q not in\n%s", c.want, e.out)
		}
		if strings.Contains(e.out.String(), "KEV / EPSS: updated") != c.got {
			t.Errorf("updated logged: %v\n%s", !c.got, e.out)
		}
	}
}

// A module streams findings through the host's sink while it runs; one about something other than the host (its
// host has a ":") goes to the org's file, not the host's.
func TestSinkAndOrgLevelFinding(t *testing.T) {
	e := newEnv(t)
	withHealth(t, func(ctx *check.Ctx, h config.Host, _ map[string]any, _ string, _ check.Facts) ([]finding.Finding, error) {
		f := misconfig(h, "streamed")
		ctx.Sink(h.Name)(&f)
		ext := misconfig(h, "external-port")
		ext.Host = "ext:203.0.113.10"
		return []finding.Finding{misconfig(h, "returned"), ext}, nil
	})
	o := e.org(nil, e.here())
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 0 {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	envDir := report.EnvDir(e.paths, "t1", config.DefaultEnv)
	host := ids(runFindings(t, envDir, "web-01"))
	if !slices.Contains(host, "streamed") || !slices.Contains(host, "returned") || slices.Contains(host, "external-port") {
		t.Errorf("host file: %q", host)
	}
	org := runFindings(t, envDir, report.OrgHost)
	if len(org) != 1 || org[0].ID != "external-port" || org[0].Host != "ext:203.0.113.10" || org[0].Priority == nil {
		t.Errorf("org file: %+v", org)
	}
}

// A policy that breaks before the first finding is prioritized fails the host's file: nothing more is added, the
// run stops with the error and is marked failed.
func TestPolicyBrokenBeforeFindings(t *testing.T) {
	e := newEnv(t)
	withHealth(t, func(_ *check.Ctx, h config.Host, _ map[string]any, _ string, _ check.Facts) ([]finding.Finding, error) {
		e.brokenPolicy()
		return []finding.Finding{misconfig(h, "a"), misconfig(h, "b")}, nil
	})
	o := e.org(nil, e.here())
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 {
		t.Fatalf("rc 0\n%s", e.out)
	}
	if !strings.Contains(e.out.String(), "  ! ") || strings.Contains(e.out.String(), "done: ") {
		t.Fatal(e.out)
	}
	runs, _ := filepath.Glob(filepath.Join(report.EnvDir(e.paths, "t1", config.DefaultEnv), "20*"))
	if len(runs) != 1 {
		t.Fatal(runs)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "hosts", "web-01", "findings.json.gz")); !os.IsNotExist(err) {
		t.Errorf("host file written: %v", err)
	}
	if st := readStatus(t, runs[0]); st["state"] != "failed" {
		t.Errorf("status %v", st["state"])
	}
}

// The host's file can't be started (its directory is a file): the run stops with that error.
func TestHostFileCannotStart(t *testing.T) {
	e := newEnv(t)
	withHealth(t, func(ctx *check.Ctx, h config.Host, _ map[string]any, out string, _ check.Facts) ([]finding.Finding, error) {
		must(t, os.RemoveAll(out))
		must(t, os.WriteFile(out, nil, 0o644))
		f := misconfig(h, "streamed")
		ctx.Sink(h.Name)(&f)
		return nil, nil
	})
	o := e.org(nil, e.here())
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 {
		t.Fatalf("rc 0\n%s", e.out)
	}
	if !strings.Contains(e.out.String(), "  ! ") || !strings.Contains(e.out.String(), errNotDir) ||
		strings.Contains(e.out.String(), "done: ") {
		t.Fatal(e.out)
	}
}

// A damaged previous state of the host only costs its due dates' history: logged, the run finishes.
func TestHostPrevDamaged(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	o := e.org(nil, e.here())
	envDir := report.EnvDir(e.paths, "t1", config.DefaultEnv)
	cur := filepath.Join(envDir, report.Current, "hosts", "web-01")
	must(t, os.MkdirAll(cur, 0o755))
	must(t, os.WriteFile(filepath.Join(cur, "findings.json.gz"), []byte("not gzip"), 0o644))
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 0 {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	for _, want := range []string{"previous state of web-01: ", "(due dates count from this scan)", "done: "} {
		if !strings.Contains(e.out.String(), want) {
			t.Errorf("%q not in\n%s", want, e.out)
		}
	}
	if got := runFindings(t, envDir, "web-01"); len(got) == 0 {
		t.Error("no findings written")
	}
}

// An org-level finding that can't be written fails the org's file: it is aborted and the run stops.
func TestOrgFileFails(t *testing.T) {
	e := newEnv(t)
	withHealth(t, func(_ *check.Ctx, h config.Host, _ map[string]any, _ string, _ check.Facts) ([]finding.Finding, error) {
		ext := misconfig(h, "external-port")
		ext.Host = "ext:203.0.113.10"
		ext.Args = map[string]any{"bad": make(chan int)} // not JSON
		return []finding.Finding{ext}, nil
	})
	o := e.org(nil, e.here())
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 {
		t.Fatalf("rc 0\n%s", e.out)
	}
	if !strings.Contains(e.out.String(), "chan int") || strings.Contains(e.out.String(), "done: ") {
		t.Fatal(e.out)
	}
	runs, _ := filepath.Glob(filepath.Join(report.EnvDir(e.paths, "t1", config.DefaultEnv), "20*"))
	if len(runs) != 1 {
		t.Fatal(runs)
	}
	org := filepath.Join(runs[0], "hosts", report.OrgHost)
	if left, _ := filepath.Glob(filepath.Join(org, "*")); len(left) != 0 {
		t.Errorf("org file or its temp left: %q", left)
	}
	if _, err := os.Stat(filepath.Join(runs[0], "hosts", "web-01", "findings.json.gz")); err != nil {
		t.Errorf("host file: %v", err)
	}
}

// No hosts and no org checks: a broken policy still fails the run.
func TestNoHostsBrokenPolicy(t *testing.T) {
	e := newEnv(t)
	o := e.org(nil, e.here())
	e.brokenPolicy()
	if rc := e.scanner().run(context.Background(), o, config.DefaultEnv, nil, Options{}, Plan{}, nil, t.TempDir()); rc != 1 {
		t.Fatalf("rc 0\n%s", e.out)
	}
	if !strings.Contains(e.out.String(), "  ! ") || strings.Contains(e.out.String(), "done: ") {
		t.Fatal(e.out)
	}
}

// The run's report can't be finished (summary.md is a non-empty directory): the run fails and is marked so.
func TestFinishRunFails(t *testing.T) {
	e := newEnv(t)
	withHealth(t, func(ctx *check.Ctx, h config.Host, _ map[string]any, _ string, _ check.Facts) ([]finding.Finding, error) {
		return nil, os.MkdirAll(filepath.Join(ctx.RunDir, "summary.md", "x"), 0o755)
	})
	o := e.org(nil, e.here())
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 {
		t.Fatalf("rc 0\n%s", e.out)
	}
	if !strings.Contains(e.out.String(), "summary.md") || strings.Contains(e.out.String(), "done: ") {
		t.Fatal(e.out)
	}
	runs, _ := filepath.Glob(filepath.Join(report.EnvDir(e.paths, "t1", config.DefaultEnv), "20*"))
	if st := readStatus(t, runs[0]); st["state"] != "failed" {
		t.Errorf("status %v", st["state"])
	}
}
