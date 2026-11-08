package report

import (
	"path/filepath"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// TestPrevIndex: the clock carries over from the current state; findings saved before 0.5 (no first_seen) take
// the oldest kept run that had them, and fix_since the oldest run where the fix was installable.
func TestPrevIndex(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	look, err := PrevIndex(env)
	must(t, err)
	if look(new(finding.Finding)) != nil {
		t.Fatal("no state yet: nothing is known")
	}
	hosts := []string{"web-01"}
	mods := map[string][]string{"web-01": {"os_packages"}}
	vendor := f(t, map[string]any{"id": "CVE-A", "fix_state": "vendor", "priority": "P2"})
	ready := f(t, map[string]any{"id": "CVE-A", "fix_state": "available", "priority": "P2"})
	other := f(t, map[string]any{"id": "CVE-B", "priority": "P3"})
	writeRun(t, env, "2026-09-01_030000", []finding.Finding{vendor}, hosts, mods, nil, nil)
	writeRun(t, env, "2026-09-20_030000", []finding.Finding{ready, other}, hosts, mods, nil, nil)
	writeRun(t, env, "2026-10-01_030000", []finding.Finding{ready, other}, hosts, mods, nil, nil)
	_, err = UpdateCurrent(env, false, true)
	must(t, err)
	look, err = PrevIndex(env)
	must(t, err)
	a, b := look(&ready), look(&other)
	if a == nil || a.FirstSeen != "2026-09-01" || a.FixSince != "2026-09-20" || b == nil || b.FirstSeen != "2026-09-20" {
		t.Fatalf("migrated from the runs: %+v %+v", a, b)
	}
	if look(new(finding.Finding)) != nil {
		t.Fatal("an unknown finding is new")
	}
	// once saved with first_seen, the state wins over the runs
	seen := ready
	seen.FirstSeen, seen.FixSince = "2026-08-15", "2026-08-20"
	writeRun(t, env, "2026-10-02_030000", []finding.Finding{seen}, hosts, mods, nil, nil)
	_, err = UpdateCurrent(env, false, true)
	must(t, err)
	look, err = PrevIndex(env)
	must(t, err)
	if a := look(&ready); a == nil || a.FirstSeen != "2026-08-15" || a.FixSince != "2026-08-20" {
		t.Fatalf("stored clock: %+v", a)
	}
}
