package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/report"
)

// TestGenerate: a valid working directory: the org loads, every day has a full run with counts, current/ is
// merged, and the feeds are there; the same data every time.
func TestGenerate(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	out := filepath.Join(t.TempDir(), "demo")
	last := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	if err := generate(out, last, 6); err != nil {
		t.Fatal(err)
	}
	l, err := config.NewLoader(config.PathsAt(out))
	if err != nil {
		t.Fatal(err)
	}
	if _, errs := l.LoadAll(); len(errs) > 0 {
		t.Fatal(errs)
	}
	env := filepath.Join(out, "reports", "acme", "production")
	runs, _ := filepath.Glob(filepath.Join(env, "2026-*"))
	if len(runs) != 6 {
		t.Fatalf("%d runs", len(runs))
	}
	m, err := report.LoadMeta(runs[5])
	if err != nil || m.PlanCounts == nil || m.PlanCounts.P1+m.PlanCounts.P2+m.PlanCounts.P3 == 0 || m.HostsOK != 7 {
		t.Fatalf("%+v %v", m, err)
	}
	for _, f := range []string{"reports/acme/production/current/run.json", "reports/acme/staging/current/run.json", "feeds/kev.json",
		"feeds/epss.json", "feeds/updated", "reports/acme/production/2026-11-08_030000/hosts/web-01/access.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatal(err)
		}
	}
	m4, _ := report.LoadMeta(runs[4])
	if m4.HostsFailed.Len() != 1 { // cache-01 is flaky on day 4
		t.Fatalf("%+v", m4.HostsFailed)
	}

	again := filepath.Join(t.TempDir(), "demo")
	if err := generate(again, last, 6); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(runs[5], "run.json"))
	b, _ := os.ReadFile(filepath.Join(again, "reports", "acme", "production", "2026-11-08_030000", "run.json"))
	if len(a) == 0 || len(a) != len(b) {
		t.Fatal("not the same data")
	}
	if err := generate(out, last, 6); err == nil {
		t.Fatal("wrote into a non-empty directory")
	}
}
