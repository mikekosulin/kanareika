package report

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// Ports of the report tests in tests/test_core.py.

// f: a vulnerability finding with defaults, as _f in the Python tests; kw overrides fields by JSON name.
func f(t *testing.T, kw map[string]any) finding.Finding {
	t.Helper()
	m := map[string]any{"org": "acme", "host": "web-01", "module": "os_packages", "kind": "vuln", "id": "CVE-1",
		"pkg": "openssl", "installed": "1", "fixed": "2", "severity": "HIGH", "exposure": 1, "target": "os"}
	for k, v := range kw {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	var out finding.Finding
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func ids(fs []finding.Finding) []string {
	out := []string{}
	for _, x := range fs {
		out = append(out, x.ID)
	}
	return out
}

func TestDiffAndPlan(t *testing.T) {
	a := []finding.Finding{f(t, map[string]any{"id": "CVE-1", "priority": "P2"}), f(t, map[string]any{"id": "CVE-2", "priority": "P3"})}
	b := []finding.Finding{f(t, map[string]any{"id": "CVE-2", "priority": "P3"}),
		f(t, map[string]any{"id": "CVE-3", "priority": "P1", "fixed": "3"})}
	newF, gone := Diff(a, b, nil)
	if !slices.Equal(ids(newF), []string{"CVE-3"}) || !slices.Equal(ids(gone), []string{"CVE-1"}) {
		t.Fatalf("new %v gone %v", ids(newF), ids(gone))
	}
	g := PatchPlan(b).Get("web-01")[0]
	if g.Pkg != "openssl" || deref(g.Priority) != "P1" || !slices.Equal(sortedKeys(g.Fixed), []string{"2", "3"}) || len(g.CVEs) != 2 {
		t.Fatalf("plan group %+v", g)
	}
}

// writeRun: a finished run as _run in the Python tests.
func writeRun(t *testing.T, env, runID string, findings []finding.Finding, hosts []string, byHost map[string][]string,
	selection *Selection, merr map[string][]string) {
	t.Helper()
	d := filepath.Join(env, runID)
	for _, h := range hosts {
		must(t, os.MkdirAll(filepath.Join(d, "hosts", h), 0o755))
		must(t, os.WriteFile(filepath.Join(d, "hosts", h, "facts.json"), []byte(`{"os_release": {"PRETTY_NAME": "X"}, "uname": "Linux 1 x"}`), 0o644))
	}
	must(t, os.MkdirAll(d, 0o755))
	if selection == nil {
		selection = &Selection{Groups: []string{}, Hosts: []string{}, Modules: []string{}}
	}
	mods := map[string]bool{}
	for _, ms := range byHost {
		for _, m := range ms {
			mods[m] = true
		}
	}
	meta := map[string]any{"org": "o", "env": "e", "run_id": runID, "started": runID, "finished": runID,
		"selection": selection, "hosts_scanned": hosts, "hosts_failed": map[string]string{}, "module_errors": orEmpty(merr),
		"modules_by_host": byHost, "modules": sortedKeys(mods)}
	if findings == nil {
		findings = []finding.Finding{}
	}
	fh, err := os.Create(filepath.Join(d, "findings.json.gz"))
	must(t, err)
	gz := gzip.NewWriter(fh)
	must(t, json.NewEncoder(gz).Encode(findings))
	must(t, gz.Close())
	must(t, fh.Close())
	b, _ := json.Marshal(meta)
	must(t, os.WriteFile(filepath.Join(d, "run.json"), b, 0o644))
}

func orEmpty[V any](m map[string]V) map[string]V {
	if m == nil {
		return map[string]V{}
	}
	return m
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCurrentStateMergesPartialRescans(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	a1 := f(t, map[string]any{"host": "a", "id": "CVE-A", "priority": "P2"})
	b1 := f(t, map[string]any{"host": "b", "id": "CVE-B", "priority": "P2"})
	accA := f(t, map[string]any{"host": "a", "module": "access", "kind": "misconfig", "id": "ssh-password-auth", "priority": "P2", "fixed": ""})
	writeRun(t, env, "2026-11-01_100000", []finding.Finding{a1, b1, accA}, []string{"a", "b"},
		map[string][]string{"a": {"os_packages", "access"}, "b": {"os_packages"}}, nil, nil)
	// partial: only access on host a, the password finding is gone
	writeRun(t, env, "2026-11-01_110000", nil, []string{"a"}, map[string][]string{"a": {"access"}},
		&Selection{Hosts: []string{"a"}, Modules: []string{"access"}}, nil)
	// partial: os_packages on b failed -> b's old data must stay
	writeRun(t, env, "2026-11-01_120000", nil, []string{"b"}, map[string][]string{"b": {"os_packages"}},
		&Selection{Hosts: []string{"b"}}, map[string][]string{"b": {"os_packages: trivy error"}})
	cur, err := UpdateCurrent(env, false, true)
	must(t, err)
	meta, findings, err := LoadRun(cur)
	must(t, err)
	got := ids(findings)
	slices.Sort(got)
	if !slices.Equal(got, []string{"CVE-A", "CVE-B"}) { // access fixed on a, b kept despite module error
		t.Fatalf("findings %v", got)
	}
	if meta.Sources["a"]["access"] != "2026-11-01_110000" || meta.Sources["a"]["os_packages"] != "2026-11-01_100000" {
		t.Fatalf("sources %v", meta.Sources)
	}
	if e, _ := meta.ModuleErrors.Get("b"); meta.ModuleErrors.Len() != 1 || !slices.Equal(e, []string{"os_packages: trivy error"}) {
		t.Fatalf("module errors %+v", meta.ModuleErrors)
	}
	var view View
	must(t, json.Unmarshal(readFile(t, filepath.Join(cur, "view.json")), &view))
	if deref(view.Prev) != "2026-11-01_100000" { // compared with the latest FULL run only
		t.Fatalf("prev %v", deref(view.Prev))
	}
	if p, _ := isPartialDir(filepath.Join(env, "2026-11-01_100000")); p {
		t.Fatal("full run seen as partial")
	}
}

func TestEnvLockRefusesSecondScan(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	l, err := EnvLock(env, false)
	must(t, err)
	var busy *Busy
	if _, err := EnvLock(env, false); !errors.As(err, &busy) {
		t.Fatalf("second lock: %v", err)
	}
	must(t, l.Unlock())
	l, err = EnvLock(env, false) // released
	must(t, err)
	must(t, l.Unlock())
}

func TestPruneKeepsRecentFullAndPartial(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	for i := range 5 {
		writeRun(t, env, "2026-11-0"+itoa(i+1)+"_100000", nil, []string{"a"}, map[string][]string{"a": {"os_packages"}}, nil, nil)
	}
	for i := range 3 {
		writeRun(t, env, "2026-11-0"+itoa(i+1)+"_120000", nil, []string{"a"}, map[string][]string{"a": {"access"}},
			&Selection{Hosts: []string{"a"}}, nil)
	}
	gone, err := Prune(config.PathsAt(t.TempDir()), env, 2, 1, false)
	must(t, err)
	var left []string
	ents, _ := os.ReadDir(env)
	for _, e := range ents {
		left = append(left, e.Name())
	}
	if !slices.Equal(left, []string{"2026-11-03_120000", "2026-11-04_100000", "2026-11-05_100000"}) || len(gone) != 5 {
		t.Fatalf("left %v, gone %v", left, gone)
	}
}

func TestPruneUsesSettings(t *testing.T) {
	home := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(home, "policy"), 0o755))
	must(t, os.WriteFile(filepath.Join(home, "policy", "settings.yml"), []byte("retention:\n  keep_full: 1\n  keep_partial: 0\n"), 0o644))
	env := filepath.Join(t.TempDir(), "e")
	for i := range 3 {
		writeRun(t, env, "2026-11-0"+itoa(i+1)+"_100000", nil, []string{"a"}, map[string][]string{"a": {"os_packages"}}, nil, nil)
	}
	writeRun(t, env, "2026-11-01_120000", nil, []string{"a"}, nil, &Selection{Hosts: []string{"a"}}, nil)
	gone, err := Prune(config.PathsAt(home), env, KeepDefault, KeepDefault, true)
	must(t, err)
	if !slices.Equal(gone, []string{"2026-11-01_100000", "2026-11-02_100000", "2026-11-01_120000"}) {
		t.Fatalf("gone %v", gone)
	}
	if ents, _ := os.ReadDir(env); len(ents) != 4 { // dry run
		t.Fatalf("dry run deleted: %d left", len(ents))
	}
}

func TestActionsSplitByFixState(t *testing.T) {
	fs := []finding.Finding{
		f(t, map[string]any{"id": "CVE-BP", "pkg": "sqlite-libs", "priority": "P2", "backported": true}),
		f(t, map[string]any{"id": "CVE-UP", "pkg": "openssl", "priority": "P2", "fix_state": "available", "repo_version": "3.5.9"}),
		f(t, map[string]any{"id": "CVE-V", "pkg": "rsync", "priority": "P1", "kev": true, "fix_state": "vendor"}),
		f(t, map[string]any{"id": "CVE-K", "pkg": "kernel-core", "installed": "5.14.0-575.el9", "priority": "P1", "kernel": true,
			"fix_state": "reboot", "repo_version": "5.14.0-759.el9"}),
		f(t, map[string]any{"id": "CVE-NEW", "pkg": "kernel-core", "installed": "5.14.0-759.el9", "priority": "P4", "inactive": true,
			"pending_reboot": true, "target": "os: new kernel (reboot pending)"}),
	}
	if c := CountsOf(fs); c.Backported != 1 || c.P2 != 1 {
		t.Fatalf("counts %+v", c)
	}
	osName := "CentOS Stream 9"
	facts := map[string]Fact{"web-01": {OS: &osName}}
	rows := PlanRows(PatchPlan(fs))
	if slices.ContainsFunc(rows, func(r PlanRow) bool { return r.Pkg == "sqlite-libs" }) {
		t.Fatal("backported package in the plan")
	}
	by := map[string]Action{}
	for _, a := range BuildActions(rows, nil, facts) {
		by[a.Cat] = a
	}
	if len(by) != 3 || by["kernel"].Cat == "" || by["os"].Cat == "" || by["vendor"].Cat == "" { // the pending kernel is not an "old kernel"
		t.Fatalf("categories %v", by)
	}
	if by["kernel"].Msg != "act.reboot" || by["kernel"].Detail != "5.14.0-575.el9 → 5.14.0-759.el9" {
		t.Fatalf("kernel %+v", by["kernel"])
	}
	pk := func(a Action) []string {
		var out []string
		for _, p := range a.Packages {
			out = append(out, p.Pkg)
		}
		return out
	}
	if !slices.Equal(pk(by["os"]), []string{"openssl"}) || !slices.Equal(pk(by["vendor"]), []string{"rsync"}) ||
		deref(by["vendor"].Priority) != "P1" {
		t.Fatalf("os %v vendor %v", pk(by["os"]), pk(by["vendor"]))
	}
	_, gone := Diff([]finding.Finding{f(t, map[string]any{"id": "CVE-BP", "pkg": "sqlite-libs"})}, fs[:1], nil)
	if !slices.Equal(ids(gone), []string{"CVE-BP"}) { // a backport counts as resolved
		t.Fatalf("gone %v", ids(gone))
	}
}

// A view written by newer code is left alone; an older one is rebuilt from the same data.
func TestCurrentViewVersion(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	writeRun(t, env, "2026-11-01_100000", []finding.Finding{f(t, map[string]any{"priority": "P2"})}, []string{"web-01"},
		map[string][]string{"web-01": {"os_packages"}}, nil, nil)
	cur, err := UpdateCurrent(env, false, true)
	must(t, err)
	vf := filepath.Join(cur, "view.json")
	for _, c := range []struct {
		stored, want int
	}{{ViewVersion + 1, ViewVersion + 1}, {ViewVersion - 1, ViewVersion}, {ViewVersion, ViewVersion}} {
		must(t, os.WriteFile(vf, []byte(`{"version": `+itoa(c.stored)+`}`), 0o644))
		_, err := UpdateCurrent(env, false, true)
		must(t, err)
		var v struct{ Version int }
		must(t, json.Unmarshal(readFile(t, vf), &v))
		if v.Version != c.want {
			t.Errorf("stored %d: got %d, want %d", c.stored, v.Version, c.want)
		}
	}
	if p, err := UpdateCurrent(filepath.Join(t.TempDir(), "empty"), false, true); p != "" || err != nil {
		t.Fatalf("empty env: %q %v", p, err)
	}
}

// While a scan holds the lock, the dashboard gets the existing snapshot instead of waiting.
func TestCurrentBusyReturnsSnapshot(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	l, err := EnvLock(env, false)
	must(t, err)
	if p, err := UpdateCurrent(env, false, false); p != "" || err != nil {
		t.Fatalf("no snapshot yet: %q %v", p, err)
	}
	must(t, os.MkdirAll(filepath.Join(env, Current), 0o755))
	must(t, os.WriteFile(filepath.Join(env, Current, "view.json"), []byte(`{}`), 0o644))
	if p, err := UpdateCurrent(env, false, false); p != filepath.Join(env, Current) || err != nil {
		t.Fatalf("snapshot: %q %v", p, err)
	}
	must(t, l.Unlock())
}

func TestSaveRunAndHistory(t *testing.T) {
	home := t.TempDir()
	p := config.PathsAt(home)
	env := EnvDir(p, "acme", "production")
	writeRun(t, env, "2026-11-01_100000", []finding.Finding{f(t, map[string]any{"priority": "P2"})}, []string{"web-01"},
		map[string][]string{"web-01": {"os_packages"}}, nil, nil)
	run := filepath.Join(env, "2026-11-02_100000")
	must(t, os.MkdirAll(run, 0o755))
	meta := &Meta{Org: "acme", Env: "production", RunID: "2026-11-02_100000", HostsScanned: []string{"web-01"}, HostsOK: 1,
		Selection: Selection{Groups: []string{}, Hosts: []string{}, Modules: []string{}}, Modules: []string{"os_packages"}}
	must(t, SaveRun(run, meta, []finding.Finding{f(t, map[string]any{"id": "CVE-2", "priority": "P1"})}))
	var v View
	must(t, json.Unmarshal(readFile(t, filepath.Join(run, "view.json")), &v))
	if deref(v.Prev) != "2026-11-01_100000" || v.New.Total != 1 || v.Resolved.Total != 1 || v.Meta.PlanCounts == nil ||
		v.Meta.PlanCounts.P1 != 1 {
		t.Fatalf("view %+v", v)
	}
	m, err := LoadMeta(run)
	must(t, err)
	if m.Counts["P1"] != 1 || m.PlanCounts.P1 != 1 {
		t.Fatalf("meta counts %+v %+v", m.Counts, m.PlanCounts)
	}
	if !exists(filepath.Join(run, "summary.md")) {
		t.Fatal("no summary.md")
	}
	h, err := HistoryTable(p, "acme", "production")
	must(t, err)
	want := "run                   hosts  fail   P1    P2    P3    P4  accepted  scope\n" +
		"------------------------------------------------------------------------------------------\n" +
		"2026-11-01_100000         0     0     0     0     0     0         0  all\n" +
		"2026-11-02_100000         1     0     1     0     0     0         0  all"
	if h != want {
		t.Fatalf("history:\n%s", h)
	}
}

// Fields this version does not know survive a rewrite of run.json; hosts_failed keeps its order.
func TestMetaRoundTrip(t *testing.T) {
	in := `{"org":"o","env":"e","run_id":"r","trivy_version":null,"started":"s","finished":"f","selection":{},` +
		`"modules":[],"hosts_scanned":[],"hosts_ok":0,"hosts_failed":{"z":"x","a":"y"},"module_errors":{},` +
		`"feeds_updated":null,"future":{"k":[1,2]}}`
	var m Meta
	must(t, json.Unmarshal([]byte(in), &m))
	if !slices.Equal(m.HostsFailed.Keys, []string{"z", "a"}) {
		t.Fatalf("order %v", m.HostsFailed.Keys)
	}
	out, err := pyfmt.Marshal(m)
	must(t, err)
	sameJSON(t, "meta", []byte(in), out)
}
