package report

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
)

var errBoom = errors.New("boom")

// swap replaces a seam for the duration of the test.
func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// regularFile creates a regular file and returns its path.
func regularFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "file")
	must(t, os.WriteFile(p, []byte("x"), 0o644))
	return p
}

// blockWith makes path a non-empty directory, so nothing can be written or renamed onto it.
func blockWith(t *testing.T, path string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Join(path, "x"), 0o755))
}

func writeText(t *testing.T, path, s string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(s), 0o644))
}

// leftovers: temporary files writeAtomic left in dir.
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	must(t, err)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") && strings.Contains(e.Name(), ".json") {
			out = append(out, e.Name())
		}
	}
	return out
}

func fullRun(t *testing.T, env, id string, fs []finding.Finding) {
	t.Helper()
	writeRun(t, env, id, fs, []string{"web-01"}, map[string][]string{"web-01": {"os_packages"}}, nil, nil)
}

func TestBusyError(t *testing.T) {
	if got := (&Busy{Env: "reports/acme/production"}).Error(); got != "a scan is already running in reports/acme/production" {
		t.Fatal(got)
	}
}

func TestEnvLockErrors(t *testing.T) {
	if _, err := EnvLock(filepath.Join(regularFile(t), "e"), false); err == nil {
		t.Error("env under a regular file")
	}
	env := filepath.Join(t.TempDir(), "e")
	must(t, os.MkdirAll(filepath.Join(env, ".lock"), 0o755))
	if _, err := EnvLock(env, false); err == nil {
		t.Error(".lock is a directory")
	}

	swap(t, &flock, func(*os.File, bool) (bool, error) { return false, errBoom })
	env = filepath.Join(t.TempDir(), "e")
	var busy *Busy
	if _, err := EnvLock(env, true); !errors.Is(err, errBoom) || errors.As(err, &busy) {
		t.Errorf("lock error: %v", err)
	}
}

func TestLoadFindingsFormats(t *testing.T) {
	dir := t.TempDir()
	if fs, err := LoadFindings(dir); err != nil || fs == nil || len(fs) != 0 {
		t.Errorf("none: %v %v", fs, err)
	}
	writeText(t, filepath.Join(dir, "findings.json"), `[{"host": "web-01", "id": "CVE-2026-0001", "kind": "vuln"}]`)
	fs, err := LoadFindings(dir)
	if err != nil || !slices.Equal(ids(fs), []string{"CVE-2026-0001"}) || fs[0].Host != "web-01" {
		t.Errorf("plain findings.json of an older run: %v %v", fs, err)
	}
	writeText(t, filepath.Join(dir, "findings.json"), `[{`)
	if _, err := LoadFindings(dir); err == nil || !strings.Contains(err.Error(), dir) {
		t.Errorf("broken findings.json: %v", err)
	}
	writeText(t, filepath.Join(dir, "findings.json.gz"), "not gzip")
	if _, err := LoadFindings(dir); err == nil {
		t.Error("broken findings.json.gz")
	}
}

func TestLoadMetaErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadMeta(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, _, err := LoadRun(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadRun missing: %v", err)
	}
	if _, err := isPartialDir(dir); err == nil {
		t.Error("isPartialDir missing")
	}
	writeText(t, filepath.Join(dir, "run.json"), `[]`)
	if _, err := LoadMeta(dir); err == nil || !strings.Contains(err.Error(), "run.json") {
		t.Errorf("not an object: %v", err)
	}
}

func TestMetaMarshalFillsLists(t *testing.T) {
	b, err := json.Marshal(Meta{Org: "acme"})
	must(t, err)
	var m map[string]any
	must(t, json.Unmarshal(b, &m))
	if !reflect.DeepEqual(m["modules"], []any{}) || !reflect.DeepEqual(m["hosts_scanned"], []any{}) || m["org"] != "acme" {
		t.Fatalf("got %s", b)
	}
	if _, err := json.Marshal(Meta{Extra: map[string]json.RawMessage{"future": json.RawMessage(`{`)}}); err == nil {
		t.Error("a broken extra value cannot be written")
	}
}

func TestPreviousRunErrors(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	writeText(t, filepath.Join(env, "2026-11-01_100000", "run.json"), `{`)
	run := filepath.Join(env, "2026-11-02_100000")
	if _, err := PreviousRun(run, true); err == nil {
		t.Error("fullOnly reads every earlier run.json")
	}
	if _, err := PreviousRun(run, false); err == nil {
		t.Error("the previous run cannot be loaded")
	}
}

func TestRunsMissingEnv(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	if r := Runs(p, "acme", "production"); r != nil {
		t.Errorf("runs %v", r)
	}
	h, err := HistoryTable(p, "acme", "production")
	if err != nil || strings.Count(h, "\n") != 1 {
		t.Errorf("history of nothing: %q %v", h, err)
	}
}

func TestHistoryTableBrokenRun(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	writeText(t, filepath.Join(EnvDir(p, "acme", "production"), "2026-11-01_100000", "run.json"), `{`)
	if _, err := HistoryTable(p, "acme", "production"); err == nil {
		t.Error("a broken run.json is an error")
	}
}

func newMeta() *Meta {
	return &Meta{Org: "acme", Env: "production", RunID: "2026-11-02_100000", HostsScanned: []string{"web-01"}, HostsOK: 1,
		Selection: Selection{Groups: []string{}, Hosts: []string{}, Modules: []string{}}, Modules: []string{"os_packages"}}
}

func TestSaveRunErrors(t *testing.T) {
	one := []finding.Finding{f(t, map[string]any{"priority": "P2"})}

	if err := SaveRun(filepath.Join(t.TempDir(), "missing"), newMeta(), one); err == nil {
		t.Error("run directory missing")
	}

	env := filepath.Join(t.TempDir(), "e")
	writeText(t, filepath.Join(env, "2026-11-01_100000", "run.json"), `{`)
	run := filepath.Join(env, "2026-11-02_100000")
	must(t, os.MkdirAll(run, 0o755))
	if err := SaveRun(run, newMeta(), one); err == nil {
		t.Error("a broken earlier run")
	}

	run = t.TempDir()
	nan := f(t, map[string]any{"priority": "P2"})
	nan.Args = map[string]any{"score": math.NaN()}
	if err := SaveRun(run, newMeta(), []finding.Finding{nan}); err == nil {
		t.Error("findings that cannot be encoded")
	}
	if exists(filepath.Join(run, "findings.json.gz")) || len(leftovers(t, run)) != 0 {
		t.Errorf("a failed write leaves nothing behind: %v", leftovers(t, run))
	}

	for _, name := range []string{"run.json", "view.json", "summary.md"} {
		run := filepath.Join(t.TempDir(), "2026-11-02_100000")
		blockWith(t, filepath.Join(run, name))
		if err := SaveRun(run, newMeta(), one); err == nil {
			t.Errorf("%s cannot be written", name)
		}
		if l := leftovers(t, run); len(l) != 0 {
			t.Errorf("%s: temporary files left: %v", name, l)
		}
	}
}

func TestSaveRunPartialHasNoPrev(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	fullRun(t, env, "2026-11-01_100000", []finding.Finding{f(t, map[string]any{"priority": "P2"})})
	run := filepath.Join(env, "2026-11-02_100000")
	must(t, os.MkdirAll(run, 0o755))
	m := newMeta()
	m.Selection.Hosts = []string{"web-01"}
	must(t, SaveRun(run, m, nil))
	var v View
	must(t, json.Unmarshal(readFile(t, filepath.Join(run, "view.json")), &v))
	if v.Prev != nil || v.New != nil {
		t.Fatalf("a partial run is compared with nothing: %v %+v", v.Prev, v.New)
	}
	fs, err := LoadFindings(run)
	if err != nil || fs == nil || len(fs) != 0 {
		t.Fatalf("nil findings are written as []: %v %v", fs, err)
	}
}

func TestWriteMetaAndView(t *testing.T) {
	dir := t.TempDir()
	must(t, WriteMeta(dir, &Meta{Org: "acme", RunID: "2026-11-01_100000"}))
	m, err := LoadMeta(dir)
	if err != nil || m.Org != "acme" || m.RunID != "2026-11-01_100000" {
		t.Fatalf("%+v %v", m, err)
	}
	if !strings.HasPrefix(string(readFile(t, filepath.Join(dir, "run.json"))), "{\n \"org\": \"acme\",") {
		t.Errorf("run.json is indented by one space: %s", readFile(t, filepath.Join(dir, "run.json")))
	}
	bad := &Meta{Org: "acme", Extra: map[string]json.RawMessage{"future": json.RawMessage(`{`)}}
	if err := WriteMeta(dir, bad); err == nil {
		t.Error("a meta that cannot be encoded")
	}
	if err := WriteView(dir, &View{Health: map[string]any{"web-01": math.Inf(1)}}); err == nil {
		t.Error("a view that cannot be encoded")
	}
	if exists(filepath.Join(dir, "view.json")) {
		t.Error("nothing written on an encode error")
	}
}

func TestRetention(t *testing.T) {
	home := t.TempDir()
	p := config.PathsAt(home)
	writeText(t, filepath.Join(home, "policy", "settings.yml"), "retention: [\n")
	if f, pa := retention(p); f != 12 || pa != 30 {
		t.Errorf("invalid YAML: %d %d", f, pa)
	}
	swap(t, &policy, func(config.Paths, string) ([]byte, error) { return nil, errBoom })
	if f, pa := retention(p); f != 12 || pa != 30 {
		t.Errorf("unreadable settings: %d %d", f, pa)
	}
}

func TestPruneEdgeCases(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	if gone, err := Prune(p, filepath.Join(t.TempDir(), "missing"), 1, 1, false); err != nil || gone == nil || len(gone) != 0 {
		t.Errorf("missing env: %v %v", gone, err)
	}
	if _, err := Prune(p, regularFile(t), 1, 1, false); err == nil && runtime.GOOS != "windows" { // Windows: not there
		t.Error("env is a regular file")
	}

	env := filepath.Join(t.TempDir(), "e")
	old := time.Now().Add(-48 * time.Hour)
	must(t, os.MkdirAll(filepath.Join(env, Current), 0o755))
	must(t, os.MkdirAll(filepath.Join(env, ".cache"), 0o755))
	writeText(t, filepath.Join(env, "notes.txt"), "x")
	brokenOld := filepath.Join(env, "2026-11-01_090000")
	must(t, os.MkdirAll(brokenOld, 0o755))
	must(t, os.Chtimes(brokenOld, old, old))
	running := filepath.Join(env, "2026-11-01_091000")
	writeText(t, filepath.Join(running, "status.json"), "{}")
	must(t, os.Chtimes(running, old, old))
	stale := filepath.Join(env, "2026-11-01_092000")
	writeText(t, filepath.Join(stale, "status.json"), "{}")
	must(t, os.Chtimes(filepath.Join(stale, "status.json"), old, old))
	must(t, os.Chtimes(stale, old, old))
	must(t, os.MkdirAll(filepath.Join(env, "2026-11-01_093000"), 0o755)) // interrupted, but recent
	fullRun(t, env, "2026-11-01_100000", nil)

	gone, err := Prune(p, env, 5, 5, false)
	must(t, err)
	if !slices.Equal(gone, []string{"2026-11-01_090000", "2026-11-01_092000"}) {
		t.Fatalf("gone %v", gone)
	}
	var left []string
	ents, _ := os.ReadDir(env)
	for _, e := range ents {
		left = append(left, e.Name())
	}
	if want := []string{".cache", "2026-11-01_091000", "2026-11-01_093000", "2026-11-01_100000", Current, "notes.txt"}; !slices.Equal(left, want) {
		t.Fatalf("left %v", left)
	}

	writeText(t, filepath.Join(env, "2026-11-02_100000", "run.json"), `{`)
	if _, err := Prune(p, env, 5, 5, true); err == nil {
		t.Error("a broken run.json")
	}
}

// --- UpdateCurrent ---------------------------------------------------------------------------------------------

// merged: an env with one full run already folded into current/.
func merged(t *testing.T) (env, cur string) {
	t.Helper()
	env = filepath.Join(t.TempDir(), "e")
	fullRun(t, env, "2026-11-01_100000", []finding.Finding{f(t, map[string]any{"priority": "P2"})})
	cur, err := UpdateCurrent(env, false, true)
	must(t, err)
	return env, cur
}

func TestUpdateCurrentLockError(t *testing.T) {
	if _, err := UpdateCurrent(filepath.Join(regularFile(t), "e"), false, true); err == nil {
		t.Error("env under a regular file")
	}
}

func TestUpdateCurrentBrokenSnapshot(t *testing.T) {
	env, cur := merged(t)
	writeText(t, filepath.Join(cur, "run.json"), `{`)
	if _, err := UpdateCurrent(env, true, true); err == nil {
		t.Error("broken current/run.json")
	}
}

func TestUpdateCurrentRebuildErrors(t *testing.T) {
	env, cur := merged(t)
	must(t, os.Remove(filepath.Join(cur, "view.json"))) // an old view: rebuild
	writeText(t, filepath.Join(cur, "findings.json.gz"), "not gzip")
	if _, err := UpdateCurrent(env, true, true); err == nil {
		t.Error("broken current findings")
	}

	env, cur = merged(t)
	must(t, os.Remove(filepath.Join(cur, "view.json")))
	writeText(t, filepath.Join(env, "2026-11-01_090000", "run.json"), `{`) // older than the snapshot
	if _, err := UpdateCurrent(env, true, true); err == nil {
		t.Error("broken earlier run while choosing the base")
	}
}

func TestUpdateCurrentMergeErrors(t *testing.T) {
	newer := func(t *testing.T, env string) { fullRun(t, env, "2026-11-02_100000", nil) }

	t.Run("current findings", func(t *testing.T) {
		env, cur := merged(t)
		newer(t, env)
		writeText(t, filepath.Join(cur, "findings.json.gz"), "not gzip")
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("new run", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		writeText(t, filepath.Join(env, "2026-11-01_100000", "run.json"), `{`)
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("hosts dir", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		fullRun(t, env, "2026-11-01_100000", nil)
		writeText(t, filepath.Join(env, Current, "hosts"), "x")
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("host file", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		writeRun(t, env, "2026-11-01_100000", nil, []string{"web-01"}, map[string][]string{"web-01": {"access"}}, nil, nil)
		blockWith(t, filepath.Join(env, "2026-11-01_100000", "hosts", "web-01", "access.json"))
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("current dir", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		writeRun(t, env, "2026-11-01_100000", nil, nil, nil, nil, nil) // no hosts: nothing written before current/
		writeText(t, filepath.Join(env, Current), "x")
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("findings file", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		fullRun(t, env, "2026-11-01_100000", nil)
		blockWith(t, filepath.Join(env, Current, "findings.json.gz"))
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("base", func(t *testing.T) {
		env, _ := merged(t)
		writeText(t, filepath.Join(env, "2026-11-01_090000", "run.json"), `{`)
		newer(t, env)
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("run.json", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		fullRun(t, env, "2026-11-01_100000", nil)
		swap(t, &rename, func(from, to string) error {
			if filepath.Base(to) == "run.json" {
				return errBoom
			}
			return os.Rename(from, to)
		})
		if _, err := UpdateCurrent(env, true, true); !errors.Is(err, errBoom) {
			t.Errorf("got %v", err)
		}
		if l := leftovers(t, filepath.Join(env, Current)); len(l) != 0 {
			t.Errorf("temporary files left: %v", l)
		}
	})
	t.Run("view.json", func(t *testing.T) {
		env := filepath.Join(t.TempDir(), "e")
		fullRun(t, env, "2026-11-01_100000", nil)
		blockWith(t, filepath.Join(env, Current, "view.json"))
		if _, err := UpdateCurrent(env, true, true); err == nil {
			t.Error("want an error")
		}
	})
}

func TestUpdateCurrentSnapshotWithoutSources(t *testing.T) {
	env, cur := merged(t)
	m, err := LoadMeta(cur)
	must(t, err)
	m.Sources = nil
	must(t, WriteMeta(cur, m))
	fullRun(t, env, "2026-11-02_100000", nil)
	_, err = UpdateCurrent(env, true, true)
	must(t, err)
	m, err = LoadMeta(cur)
	must(t, err)
	if want := map[string]map[string]string{"web-01": {"_facts": "2026-11-02_100000", "os_packages": "2026-11-02_100000"}}; !reflect.DeepEqual(m.Sources, want) {
		t.Fatalf("sources %v", m.Sources)
	}
}

// When the latest full run is the one just merged, "new / resolved" compare with the full run before it.
func TestUpdateCurrentBaseIsPreviousFull(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	fullRun(t, env, "2026-11-01_100000", []finding.Finding{f(t, map[string]any{"id": "CVE-1", "priority": "P2"})})
	fullRun(t, env, "2026-11-02_100000", []finding.Finding{f(t, map[string]any{"id": "CVE-2", "priority": "P2"})})
	cur, err := UpdateCurrent(env, true, true)
	must(t, err)
	var v View
	must(t, json.Unmarshal(readFile(t, filepath.Join(cur, "view.json")), &v))
	if deref(v.Prev) != "2026-11-01_100000" || v.New == nil || v.New.Total != 1 || v.Resolved.Total != 1 {
		t.Fatalf("prev %v new %+v resolved %+v", deref(v.Prev), v.New, v.Resolved)
	}
}

// --- plan, actions, view details ---------------------------------------------------------------------------------

func TestCountsOfStoredPriorityNames(t *testing.T) {
	c := CountsOf([]finding.Finding{f(t, map[string]any{"priority": "accepted"}), f(t, map[string]any{"priority": "backported"}),
		f(t, map[string]any{"priority": "P9"})})
	if c.Accepted != 1 || c.Backported != 1 || c.P1+c.P2+c.P3+c.P4 != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestPlanHelpers(t *testing.T) {
	p := Plan{{Host: "web-01", Groups: []*Group{{Priority: ptr("cves"), CVEs: map[string]bool{"CVE-1": true}}}}}
	if c := PlanCountsOf(p); c.CVEs != 2 || c.P1+c.P2+c.P3+c.P4 != 0 {
		t.Errorf("counts %+v", c)
	}
	if p.Get("db-01") != nil || len(p.Get("web-01")) != 1 {
		t.Error("Get")
	}
	for _, c := range []struct {
		a, b string
		want int
	}{{"1a", "a1", -1}, {"a1", "1a", 1}, {"1.2rc", "1.2", 1}, {"1.2", "1.2rc", -1}, {"1.10", "1.9", 1}} {
		if got := vkeyCompare(c.a, c.b); got != c.want {
			t.Errorf("vkeyCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if got := vkey("2.0-rc"); !reflect.DeepEqual(got, []vtok{{true, "2"}, {false, "."}, {true, "0"}, {false, "-rc"}}) {
		t.Errorf("vkey %v", got)
	}
	if pyOpt(nil) != "None" || pyOpt(ptr("3.0")) != "3.0" {
		t.Error("pyOpt")
	}
}

func TestBuildActionsOtherKinds(t *testing.T) {
	inv := f(t, map[string]any{"kind": "inventory", "module": "packages", "id": "pkg-list", "title": "Package list", "fixed": "",
		"target": ""})
	msg := f(t, map[string]any{"kind": "misconfig", "module": "access", "id": "ssh-root", "title": "Root login", "msg": "chk.ssh_root",
		"fixed": "", "target": ""})
	by := map[string]Action{}
	for _, a := range BuildActions(nil, []*finding.Finding{&inv, &msg}, nil) {
		by[a.Title] = a
	}
	if a := by["Package list"]; a.Cat != "config" || a.Args != nil || !slices.Equal(a.Hosts, []string{"web-01"}) {
		t.Errorf("unknown kind falls back to config: %+v", a)
	}
	if a := by["Root login"]; a.Cat != "config" || a.Msg != "chk.ssh_root" || a.Args == nil || len(a.Args) != 0 {
		t.Errorf("a message key always has args: %+v", a)
	}
}

func TestBuildActionsRebootWithoutRepoVersion(t *testing.T) {
	rows := []PlanRow{{Host: "web-01", Pkg: "kernel-core", Installed: "5.14.0-575.el9", Fixed: "5.14.0-580.el9", Kernel: true,
		FixState: ptr(finding.FixReboot), Priority: ptr("P2")}}
	acts := BuildActions(rows, nil, nil)
	if len(acts) != 1 || acts[0].Cat != "kernel" || acts[0].Detail != "5.14.0-575.el9 → None" {
		t.Fatalf("%+v", acts)
	}
}

func TestSlimKeepsFlags(t *testing.T) {
	x := f(t, map[string]any{"kev": true, "epss": 0.25, "priority": "P1"})
	m := slim(&x)
	if m["kev"] != true || m["epss"] != 0.25 || m["priority"] != "P1" {
		t.Fatalf("%v", m)
	}
	y := f(t, map[string]any{"epss": 0})
	if m := slim(&y); m["kev"] != nil || m["epss"] != nil {
		t.Fatalf("false / 0 are dropped: %v", m)
	}
}

func TestBackportedRowsOrder(t *testing.T) {
	bp := func(host, pkg, id string) finding.Finding {
		return f(t, map[string]any{"host": host, "pkg": pkg, "id": id, "backported": true})
	}
	rows := backported([]finding.Finding{bp("web-02", "openssl", "CVE-1"), bp("web-01", "bash", "CVE-2"),
		bp("web-01", "openssl", "CVE-3"), bp("web-01", "openssl", "CVE-4"), f(t, nil)})
	var got []string
	for _, r := range rows {
		got = append(got, r.Host+"/"+r.Pkg+"/"+itoa(r.CVEs))
	}
	if !slices.Equal(got, []string{"web-01/openssl/2", "web-01/bash/1", "web-02/openssl/1"}) {
		t.Fatalf("%v", got)
	}
	if !slices.Equal(rows[0].IDs, []string{"CVE-4", "CVE-3"}) {
		t.Fatalf("ids newest first: %v", rows[0].IDs)
	}
}

func TestFactsSkipsIncompleteFiles(t *testing.T) {
	dir := t.TempDir()
	writeText(t, filepath.Join(dir, "hosts", "web-01", "facts.json"), `{"uname": "Linux 6.1.0 x86_64"}`)
	writeText(t, filepath.Join(dir, "hosts", "web-03", "facts.json"), `{"os_release": {}, "uname": "Linux"}`)
	got := facts(dir, []string{"web-01", "web-02", "web-03"})
	if len(got) != 1 || got["web-03"].OS != nil || got["web-03"].Kernel == nil || len(got["web-03"].Kernel) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestLimitNil(t *testing.T) {
	if got := limit[int](nil, 3); got == nil || len(got) != 0 {
		t.Errorf("nil: %v", got)
	}
	if got := limit([]int{1, 2, 3, 4}, 3); !slices.Equal(got, []int{1, 2, 3}) {
		t.Errorf("cut: %v", got)
	}
}

func TestBuildViewEdgeCases(t *testing.T) {
	dir := t.TempDir()
	writeText(t, filepath.Join(dir, "hosts", "web-01", "access.json"), `[1]`)
	one := []finding.Finding{f(t, map[string]any{"priority": "P2"})}
	meta := &Meta{HostsScanned: []string{"web-01"}}
	v := BuildView(dir, meta, one, &Prev{ID: "2026-11-01_100000", Meta: &Meta{}, Findings: one})
	if !reflect.DeepEqual(v.Access["web-01"], []any{json.Number("1")}) {
		t.Errorf("an access.json that is not an object passes through: %#v", v.Access["web-01"])
	}
	if v.New == nil || v.New.Total != 0 || v.New.Rows == nil || v.Resolved.Rows == nil {
		t.Errorf("no changes: empty lists, not null: %+v %+v", v.New, v.Resolved)
	}
}

// TestHistoryTableFixes: a 0.5 run shows fixes per priority (its totals), as the scan's last line does; a run from
// before keeps its finding rows.
func TestHistoryTableFixes(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	env := EnvDir(p, "acme", "production")
	writeText(t, filepath.Join(env, "2026-11-01_100000", "run.json"),
		`{"run_id":"2026-11-01_100000","counts":{"P1":0,"P2":0,"P3":56,"P4":291,"accepted":0}}`)
	writeText(t, filepath.Join(env, "2026-11-02_100000", "run.json"),
		`{"run_id":"2026-11-02_100000","counts":{"P1":0,"P2":1,"P3":56,"P4":291,"accepted":0},"totals":{"fixes":37,"P1":0,"P2":1,"P3":11,"P4":25}}`)
	h, err := HistoryTable(p, "acme", "production")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h, "2026-11-01_100000         0     0     0     0    56   291") ||
		!strings.Contains(h, "2026-11-02_100000         0     0     0     1    11    25") {
		t.Fatalf("history:\n%s", h)
	}
	if l := (Totals{Fixes: 1, P1: 1, CVEs: 1, Hosts: 1}).Line(); !strings.HasSuffix(l, "; 1 unique CVE; 1 host with something to do") {
		t.Error(l)
	}
}
