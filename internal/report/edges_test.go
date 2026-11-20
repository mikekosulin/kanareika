package report

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// orgFinding: a finding of the org-level checks (stored in hosts/@org).
func orgFinding(t *testing.T, module, id string) finding.Finding {
	t.Helper()
	host := "external:203.0.113.5"
	if module == "k8s" {
		host = "k8s:prod"
	}
	return f(t, map[string]any{"host": host, "module": module, "kind": "exposure", "id": id, "pkg": "", "fixed": "",
		"priority": "P3"})
}

// --- UpdateCurrent: the dashboard's fold (unlocked) and the org-level file ----------------------------------------

// TestUpdateCurrentUnlockedErrors: the dashboard folds without the lock and so without MigrateEnv: a broken single
// file of current/ (rebuilding an old view) or of a run it folds stops it with an error, nothing written.
func TestUpdateCurrentUnlockedErrors(t *testing.T) {
	t.Run("rebuild", func(t *testing.T) {
		env, cur := merged(t)
		must(t, os.Remove(filepath.Join(cur, "view.json"))) // an old view: rebuilt from the same data
		writeText(t, filepath.Join(cur, "findings.json.gz"), "not gzip")
		if _, err := UpdateCurrent(env, false, true); err == nil {
			t.Error("a view rebuilt over a broken findings file")
		}
		if exists(filepath.Join(cur, "view.json")) {
			t.Error("a view written after the error")
		}
	})
	t.Run("run to fold", func(t *testing.T) {
		env, cur := merged(t)
		fullRun(t, env, "2026-11-02_100000", nil)
		run := filepath.Join(env, "2026-11-02_100000")
		writeText(t, filepath.Join(run, "findings.json.gz"), "not gzip")
		before := readFile(t, filepath.Join(cur, "run.json"))
		_, err := UpdateCurrent(env, false, true)
		if err == nil || !strings.Contains(err.Error(), run) {
			t.Errorf("want the run's error, got %v", err)
		}
		if string(readFile(t, filepath.Join(cur, "run.json"))) != string(before) {
			t.Error("current/ changed though nothing was folded")
		}
	})
}

// TestUpdateCurrentHostDirReadOnly: current/hosts that cannot take a new host's directory stops the fold (the
// host's files have nowhere to go).
func TestUpdateCurrentHostDirReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no read-only directories by mode on Windows")
	}
	env := filepath.Join(t.TempDir(), "e")
	fullRun(t, env, "2026-11-01_100000", nil) // web-01 scanned, nothing found: no findings file to link
	readOnly(t, filepath.Join(env, Current, "hosts"))
	if _, err := UpdateCurrent(env, false, true); err == nil {
		t.Error("want an error")
	}
	if exists(filepath.Join(env, Current, "run.json")) {
		t.Error("current/run.json written after the error")
	}
}

// TestUpdateCurrentFoldErrors: what stops folding a run into current/ midway, each with an error: a broken host file
// current/ keeps (read for the view), a host's merged file with nowhere to go, the org-level file broken or blocked.
func TestUpdateCurrentFoldErrors(t *testing.T) {
	t.Run("view of a kept host", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		both := map[string][]string{"a": {"os_packages"}, "b": {"os_packages"}}
		writeRun(t, env, "2026-11-01_100000", []finding.Finding{f(t, map[string]any{"host": "a", "id": "CVE-A", "priority": "P2"}),
			f(t, map[string]any{"host": "b", "id": "CVE-B", "priority": "P2"})}, []string{"a", "b"}, both, nil, nil)
		_, err := UpdateCurrent(env, false, true)
		must(t, err)
		writeText(t, hostFindingsPath(filepath.Join(env, Current), "b"), "not gzip") // b is not rescanned below
		writeRun(t, env, "2026-11-02_100000", []finding.Finding{f(t, map[string]any{"host": "a", "id": "CVE-A", "priority": "P2"})},
			[]string{"a"}, map[string][]string{"a": {"os_packages"}}, &Selection{Hosts: []string{"a"}}, nil)
		if _, err := UpdateCurrent(env, false, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("merged host file", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		// a module failed on web-01: its findings are merged with current/'s, not linked
		writeRun(t, env, "2026-11-01_100000", []finding.Finding{f(t, map[string]any{"priority": "P2"})}, []string{"web-01"},
			map[string][]string{"web-01": {"os_packages", "access"}}, nil, map[string][]string{"web-01": {"access: timeout"}})
		writeText(t, filepath.Join(env, Current, "hosts", "web-01"), "x")
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	orgRun := func(t *testing.T, env, id string, fs []finding.Finding) {
		t.Helper()
		writeRun(t, env, id, fs, []string{"web-01"}, map[string][]string{"web-01": {"os_packages", "network_external"}}, nil, nil)
	}
	t.Run("org file broken", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		orgRun(t, env, "2026-11-01_100000", []finding.Finding{orgFinding(t, "network_external", "port-22")})
		_, err := UpdateCurrent(env, true, true)
		must(t, err)
		writeText(t, hostFindingsPath(filepath.Join(env, Current), OrgHost), "not gzip")
		orgRun(t, env, "2026-11-02_100000", []finding.Finding{orgFinding(t, "network_external", "port-23")})
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("org file blocked", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		orgRun(t, env, "2026-11-01_100000", []finding.Finding{orgFinding(t, "network_external", "port-22")})
		writeText(t, filepath.Join(env, Current, "hosts", OrgHost), "x")
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
}

// TestUpdateCurrentOrgKeepsOtherModules: a partial run of one org-level module replaces current/'s findings of that
// module only; those of the other org-level modules stay, before the run's.
func TestUpdateCurrentOrgKeepsOtherModules(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	writeRun(t, env, "2026-11-01_100000", []finding.Finding{orgFinding(t, "network_external", "port-22"), orgFinding(t, "k8s", "kube-api")},
		[]string{"web-01"}, map[string][]string{"web-01": {"os_packages", "network_external", "k8s"}}, nil, nil)
	writeRun(t, env, "2026-11-02_100000", []finding.Finding{orgFinding(t, "network_external", "port-23")}, []string{"web-01"},
		map[string][]string{"web-01": {"network_external"}}, &Selection{Modules: []string{"network_external"}}, nil)
	cur, err := UpdateCurrent(env, true, true)
	must(t, err)
	if got := readIDs(t, hostFindingsPath(cur, OrgHost)); !slices.Equal(got, []string{"k8s:prod/kube-api", "external:203.0.113.5/port-23"}) {
		t.Fatalf("org findings %v", got)
	}
}

// --- runs and views ------------------------------------------------------------------------------------------------

// TestFinishRunBrokenHostFile: a run whose host file does not read is not finished: no run.json, view or summary.
func TestFinishRunBrokenHostFile(t *testing.T) {
	run := filepath.Join(t.TempDir(), "e", "2026-11-02_100000")
	writeText(t, hostFindingsPath(run, "web-01"), "not gzip")
	if err := FinishRun(run, newMeta()); err == nil {
		t.Fatal("want an error")
	}
	for _, name := range []string{"run.json", "view.json", "summary.md"} {
		if exists(filepath.Join(run, name)) {
			t.Errorf("%s written", name)
		}
	}
}

// TestWriteIntoMissingDir: run.json and view.json are written into a run that exists; a missing one is an error.
func TestWriteIntoMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	if err := WriteView(dir, &View{}); err == nil {
		t.Error("WriteView: want an error")
	}
	if err := WriteMeta(dir, newMeta()); err == nil {
		t.Error("WriteMeta: want an error")
	}
	if exists(dir) {
		t.Error("the directory was made")
	}
}

// TestRunCountsStoredPriorityNames: run.json counts a priority stored by name (accepted, backported, without the
// flags) as CountsOf does.
func TestRunCountsStoredPriorityNames(t *testing.T) {
	fs := []finding.Finding{f(t, map[string]any{"id": "CVE-1", "priority": "accepted"}),
		f(t, map[string]any{"id": "CVE-2", "priority": "backported"}), f(t, map[string]any{"id": "CVE-3", "priority": "P2"})}
	run := filepath.Join(t.TempDir(), "e", "2026-11-02_100000")
	must(t, os.MkdirAll(run, 0o755))
	must(t, SaveRun(run, newMeta(), fs))
	m, err := LoadMeta(run)
	must(t, err)
	if want := CountsOf(fs).Map(); !reflect.DeepEqual(m.Counts, want) || want["accepted"] != 1 || want["backported"] != 1 {
		t.Fatalf("counts %v, want %v", m.Counts, want)
	}
}

// TestPlanCountsParity: the view's plan counts (rows) are PlanCountsOf's (groups), Python's "cves" quirk included.
func TestPlanCountsParity(t *testing.T) {
	plan := Plan{{Host: "web-01", Groups: []*Group{
		{Priority: ptr("P1"), CVEs: map[string]bool{"CVE-1": true, "CVE-2": true}},
		{Priority: ptr("P2"), CVEs: map[string]bool{"CVE-3": true}},
		{Priority: ptr("P3"), CVEs: map[string]bool{"CVE-4": true}},
		{Priority: ptr("P4"), CVEs: map[string]bool{"CVE-5": true}},
		{Priority: ptr("cves"), CVEs: map[string]bool{"CVE-6": true}},
		{CVEs: map[string]bool{"CVE-7": true}},
	}}}
	want := PlanCountsOf(plan)
	if got := planCounts(PlanRows(plan)); got != want || want.CVEs != 8 || want.P1 != 1 {
		t.Fatalf("rows %+v, groups %+v", got, want)
	}
}

// TestBuildViewDirErrors: the view of a run stops with an error when the previous run or a host file it compares
// does not read, for a split run and one written before 0.6 alike, or when the run's hosts cannot be listed.
func TestBuildViewDirErrors(t *testing.T) {
	hosts, mods := []string{"web-01"}, map[string][]string{"web-01": {"os_packages"}}
	one := []finding.Finding{f(t, map[string]any{"priority": "P2"})}
	// env: a run, and a previous one whose host file does not read
	env := func(t *testing.T) (run, prev string) {
		t.Helper()
		env := filepath.Join(t.TempDir(), "e")
		prev = splitRun(t, env, "2026-11-01_100000", one, hosts, mods, nil)
		writeText(t, hostFindingsPath(prev, "web-01"), "not gzip")
		writeRun(t, env, "2026-11-02_100000", one, hosts, mods, nil, nil)
		return filepath.Join(env, "2026-11-02_100000"), prev
	}
	view := func(t *testing.T, run, prev string) error {
		t.Helper()
		m, err := LoadMeta(run)
		must(t, err)
		_, err = BuildViewDir(run, m, prev)
		return err
	}
	t.Run("no previous run.json", func(t *testing.T) {
		run, _ := env(t)
		if err := view(t, run, filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("previous single file", func(t *testing.T) {
		run, prev := env(t)
		writeText(t, filepath.Join(prev, "findings.json.gz"), "not gzip")
		if err := view(t, run, prev); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("previous host file, run before 0.6", func(t *testing.T) {
		run, prev := env(t)
		if legacyFile(run) == "" {
			t.Fatal("the run is not a single file")
		}
		if err := view(t, run, prev); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("previous host file, split run", func(t *testing.T) {
		run, prev := env(t)
		must(t, splitLegacy(run))
		if err := view(t, run, prev); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("hosts is a file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows lists a file as a directory that is not there")
		}
		dir := t.TempDir()
		writeText(t, filepath.Join(dir, "hosts"), "x")
		if _, err := BuildViewDir(dir, newMeta(), ""); err == nil {
			t.Error("want an error")
		}
	})
}

// --- the due date's clock ----------------------------------------------------------------------------------------

// TestPrevIndexBrokenHost: a host whose current/ file does not read has no clock (its findings start one), while
// HostPrev, asked for that host alone, says why.
func TestPrevIndexBrokenHost(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	cur := filepath.Join(env, Current)
	ok := f(t, map[string]any{"host": "web-02", "priority": "P2", "first_seen": "2026-10-01"})
	must(t, WriteHostFindings(cur, "web-02", []finding.Finding{ok}))
	writeText(t, hostFindingsPath(cur, "web-01"), "not gzip")
	look, err := PrevIndex(env)
	must(t, err)
	broken := f(t, map[string]any{"priority": "P2"})
	if c := look(&broken); c != nil {
		t.Errorf("a clock from a broken file: %+v", c)
	}
	if c := look(&ok); c == nil || c.FirstSeen != "2026-10-01" {
		t.Errorf("the next host's clock: %+v", c)
	}
	if _, err := HostPrev(env, "web-01"); err == nil {
		t.Error("HostPrev: want an error")
	}
}

// TestPrevIndexMigrationSkips: migrating clocks from old runs takes dates from run names only (a directory named
// otherwise gives none) and only for findings current/ still has.
func TestPrevIndexMigrationSkips(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	hosts, mods := []string{"web-01"}, map[string][]string{"web-01": {"os_packages"}}
	kept := f(t, map[string]any{"id": "CVE-A", "priority": "P2"})
	gone := f(t, map[string]any{"id": "CVE-B", "priority": "P2"})
	writeRun(t, env, "2026-09-01_030000", []finding.Finding{gone}, hosts, mods, nil, nil)
	writeRun(t, env, "2026-09-20_030000", []finding.Finding{kept, gone}, hosts, mods, nil, nil)
	writeRun(t, env, "notes", []finding.Finding{kept}, hosts, mods, nil, nil) // sorts after the runs; no date
	must(t, WriteHostFindings(filepath.Join(env, Current), "web-01", []finding.Finding{kept}))
	look, err := PrevIndex(env)
	must(t, err)
	if c := look(&kept); c == nil || c.FirstSeen != "2026-09-20" || c.FixSince != "2026-09-20" {
		t.Errorf("kept: %+v", c)
	}
	if c := look(&gone); c != nil {
		t.Errorf("a finding current/ no longer has: %+v", c)
	}
}
