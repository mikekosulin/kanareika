package report

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// toLegacy rewrites dir as a run written before 0.6: one findings file, no host files.
func toLegacy(t *testing.T, dir string) {
	t.Helper()
	fs, err := LoadFindings(dir)
	must(t, err)
	hfs, err := HostFiles(dir)
	must(t, err)
	must(t, WriteFindingsFile(filepath.Join(dir, "findings.json.gz"), fs))
	for _, hf := range hfs {
		must(t, os.Remove(hf.Path))
	}
}

// The dashboard (UpdateCurrent unlocked) reads older runs as they are and splits only what it folds into current/;
// a scan (locked) splits every run.
func TestUpdateCurrentSplitsOnlyWhatItFolds(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	a := f(t, map[string]any{"host": "a", "id": "CVE-A", "priority": "P2"})
	b := f(t, map[string]any{"host": "b", "id": "CVE-B", "priority": "P2"})
	mods := map[string][]string{"a": {"os_packages"}, "b": {"os_packages"}}
	r1, r2 := filepath.Join(env, "2026-11-01_100000"), filepath.Join(env, "2026-11-02_100000")
	writeRun(t, env, filepath.Base(r1), []finding.Finding{a, b}, []string{"a", "b"}, mods, nil, nil)
	writeRun(t, env, filepath.Base(r2), []finding.Finding{a, b}, []string{"a", "b"}, mods, nil, nil)
	cur, err := UpdateCurrent(env, false, true)
	must(t, err)
	for _, d := range []string{r1, r2, cur} {
		toLegacy(t, d)
	}
	legacy := func(d string) bool { return legacyFile(d) != "" }
	got := func() []string {
		_, fs, err := LoadRun(cur)
		must(t, err)
		l := ids(fs)
		slices.Sort(l)
		return l
	}

	// nothing to fold: nothing split, current/ read as it is
	_, err = UpdateCurrent(env, false, true)
	must(t, err)
	if !legacy(r1) || !legacy(r2) || !legacy(cur) {
		t.Fatal("split with nothing to fold")
	}
	if l := got(); !slices.Equal(l, []string{"CVE-A", "CVE-B"}) {
		t.Fatalf("findings %v", l)
	}

	// a new run of host a: current/ is split to fold it in, the older runs stay as they are
	writeRun(t, env, "2026-11-03_100000", nil, []string{"a"}, map[string][]string{"a": {"os_packages"}},
		&Selection{Hosts: []string{"a"}}, nil)
	_, err = UpdateCurrent(env, false, true)
	must(t, err)
	if legacy(cur) || !legacy(r1) || !legacy(r2) {
		t.Fatalf("after a fold: current legacy %v, runs %v %v", legacy(cur), legacy(r1), legacy(r2))
	}
	if l := got(); !slices.Equal(l, []string{"CVE-B"}) {
		t.Fatalf("findings after the fold %v", l)
	}

	// a scan splits every run
	_, err = UpdateCurrent(env, true, false)
	must(t, err)
	if legacy(r1) || legacy(r2) {
		t.Fatal("scan left runs unsplit")
	}
}
