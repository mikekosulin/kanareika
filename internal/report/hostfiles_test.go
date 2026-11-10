package report

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

// splitRun: a finished run stored as 0.6 writes it, one findings file per host.
func splitRun(t *testing.T, env, id string, fs []finding.Finding, hosts []string, byHost map[string][]string, sel *Selection) string {
	t.Helper()
	writeRun(t, env, id, fs, hosts, byHost, sel, nil)
	d := filepath.Join(env, id)
	must(t, splitLegacy(d))
	return d
}

// readOnly makes dir read-only for the test (nothing can be created in it).
func readOnly(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes into read-only directories")
	}
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
}

// unencodable: a finding the JSON encoder refuses (a value that is no JSON).
func unencodable(t *testing.T) finding.Finding {
	x := f(t, nil)
	x.Args = map[string]any{"bad": func() {}}
	return x
}

// tmpFiles: the temporary files a findingsWriter left in dir.
func tmpFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	must(t, err)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	return out
}

func readIDs(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	must(t, EachFindingIn(path, func(f *finding.Finding) { out = append(out, f.Host+"/"+f.ID) }))
	return out
}

func TestHostFilesErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lists a file as a directory that is not there")
	}
	dir := t.TempDir()
	writeText(t, filepath.Join(dir, "hosts"), "x")
	if _, err := HostFiles(dir); err == nil {
		t.Error("hosts is a file: want an error")
	}
	if _, err := LoadFindings(dir); err == nil {
		t.Error("LoadFindings: want an error")
	}
	if err := EachFinding(dir, func(*finding.Finding) {}); err == nil {
		t.Error("EachFinding: want an error")
	}
	if hfs, err := HostFiles(t.TempDir()); err != nil || hfs != nil {
		t.Errorf("empty dir: %v %v", hfs, err)
	}
}

func TestEachFindingInFormats(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ name, body, err string }{
		{"empty.json", "", "EOF"},
		{"null.json", "null", ""},
		{"empty-array.json", "[]", ""},
		{"object.json", `{"id":"CVE-1"}`, "want an array"},
		{"number.json", `[1]`, "unmarshal"}, // not a finding
		{"cut.json", `[{"id":"CVE-1"}`, "EOF"},
		{"bad.json", `[{"id":"CVE-1"} x]`, "invalid"},
	} {
		p := filepath.Join(dir, c.name)
		writeText(t, p, c.body)
		n := 0
		err := EachFindingIn(p, func(*finding.Finding) { n++ })
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && err == nil:
			t.Errorf("%s: want an error, read %d", c.name, n)
		case err != nil && !strings.Contains(err.Error(), p):
			t.Errorf("%s: the error names the file: %v", c.name, err)
		}
		if c.err == "" && n != 0 {
			t.Errorf("%s: %d findings", c.name, n)
		}
	}
	if err := EachFindingIn(filepath.Join(dir, "missing.json.gz"), func(*finding.Finding) {}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	gz := filepath.Join(dir, "notgz.json.gz")
	writeText(t, gz, "[]")
	if err := EachFindingIn(gz, func(*finding.Finding) {}); err == nil || !strings.Contains(err.Error(), gz) {
		t.Errorf("not gzip: %v", err)
	}
}

func TestWriteFindingsFileRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "img", "abc.json.gz")
	want := []finding.Finding{f(t, map[string]any{"id": "CVE-1"}), f(t, map[string]any{"id": "CVE-2", "host": "web-02"})}
	must(t, WriteFindingsFile(p, want))
	if got := readIDs(t, p); !slices.Equal(got, []string{"web-01/CVE-1", "web-02/CVE-2"}) {
		t.Fatalf("read back %v", got)
	}
	if st, err := os.Stat(p); err != nil || runtime.GOOS != "windows" && st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v %v", st, err)
	}
	if l := tmpFiles(t, filepath.Dir(p)); l != nil {
		t.Fatalf("temporary files left: %v", l)
	}
}

func TestWriteFindingsErrors(t *testing.T) {
	t.Run("parent is a file", func(t *testing.T) {
		p := filepath.Join(regularFile(t), "x.json.gz")
		if err := WriteFindingsFile(p, nil); err == nil {
			t.Error("WriteFindingsFile: want an error")
		}
		if err := WriteHostFindings(regularFile(t), "web-01", nil); err == nil {
			t.Error("WriteHostFindings: want an error")
		}
		if _, err := NewHostWriter(regularFile(t), "web-01"); err == nil {
			t.Error("NewHostWriter: want an error")
		}
	})
	t.Run("read-only dir", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no read-only directories by mode on Windows")
		}
		dir := t.TempDir()
		readOnly(t, dir)
		if err := WriteFindingsFile(filepath.Join(dir, "x.json.gz"), nil); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("unencodable finding", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "x.json.gz")
		if err := WriteFindingsFile(p, []finding.Finding{f(t, nil), unencodable(t)}); err == nil {
			t.Error("WriteFindingsFile: want an error")
		}
		if err := WriteHostFindings(dir, "web-01", []finding.Finding{unencodable(t)}); err == nil {
			t.Error("WriteHostFindings: want an error")
		}
		if exists(p) || exists(hostFindingsPath(dir, "web-01")) {
			t.Error("a failed write left a file in place")
		}
		if l := append(tmpFiles(t, dir), tmpFiles(t, filepath.Join(dir, "hosts", "web-01"))...); l != nil {
			t.Errorf("temporary files left: %v", l)
		}
	})
	t.Run("commit", func(t *testing.T) {
		dir := t.TempDir()
		swap(t, &rename, func(string, string) error { return errBoom })
		if err := WriteHostFindings(dir, "web-01", []finding.Finding{f(t, nil)}); !errors.Is(err, errBoom) {
			t.Errorf("got %v", err)
		}
		if l := tmpFiles(t, filepath.Join(dir, "hosts", "web-01")); l != nil {
			t.Errorf("temporary files left: %v", l)
		}
	})
}

func TestHostWriter(t *testing.T) {
	dir := t.TempDir()
	w, err := NewHostWriter(dir, "web-01")
	must(t, err)
	for _, id := range []string{"CVE-1", "CVE-2"} {
		x := f(t, map[string]any{"id": id})
		must(t, w.Add(&x))
	}
	if w.Len() != 2 {
		t.Fatalf("Len %d", w.Len())
	}
	if exists(hostFindingsPath(dir, "web-01")) {
		t.Fatal("in place before Commit")
	}
	must(t, w.Commit())
	hfs, err := HostFiles(dir)
	must(t, err)
	if len(hfs) != 1 || hfs[0].Host != "web-01" || !slices.Equal(readIDs(t, hfs[0].Path), []string{"web-01/CVE-1", "web-01/CVE-2"}) {
		t.Fatalf("host files %+v", hfs)
	}

	// Abort: nothing in place, nothing left behind; the committed file stays as it was
	w, err = NewHostWriter(dir, "web-01")
	must(t, err)
	x := f(t, map[string]any{"id": "CVE-9"})
	must(t, w.Add(&x))
	w.Abort()
	if got := readIDs(t, hostFindingsPath(dir, "web-01")); len(got) != 2 {
		t.Fatalf("Abort replaced the file: %v", got)
	}
	if l := tmpFiles(t, filepath.Join(dir, "hosts", "web-01")); l != nil {
		t.Fatalf("temporary files left: %v", l)
	}

	// a failed Commit reports the error and leaves the old file
	w, err = NewHostWriter(dir, "web-01")
	must(t, err)
	swap(t, &rename, func(string, string) error { return errBoom })
	if err := w.Commit(); !errors.Is(err, errBoom) {
		t.Fatalf("Commit: %v", err)
	}
	if got := readIDs(t, hostFindingsPath(dir, "web-01")); len(got) != 2 {
		t.Fatalf("failed Commit replaced the file: %v", got)
	}
}

func TestEachFindingReadsHostsAndLegacy(t *testing.T) {
	env := filepath.Join(t.TempDir(), "e")
	fs := []finding.Finding{f(t, map[string]any{"host": "b", "id": "CVE-B"}), f(t, map[string]any{"host": "a", "id": "CVE-A"}),
		f(t, map[string]any{"host": "external:x", "module": "network_external", "id": "port-22", "kind": "exposure"})}
	run := splitRun(t, env, "2026-11-01_100000", fs, []string{"a", "b"}, map[string][]string{"a": {"os_packages"}, "b": {"os_packages"}}, nil)
	collect := func() []string {
		var out []string
		must(t, EachFinding(run, func(f *finding.Finding) { out = append(out, f.Host+"/"+f.ID) }))
		return out
	}
	// host files: by host name (@org first)
	if got := collect(); !slices.Equal(got, []string{"external:x/port-22", "a/CVE-A", "b/CVE-B"}) {
		t.Fatalf("split run %v", got)
	}
	toLegacy(t, run)
	// the single file: in its order
	if got := collect(); !slices.Equal(got, []string{"external:x/port-22", "a/CVE-A", "b/CVE-B"}) {
		t.Fatalf("legacy run %v", got)
	}
	if err := EachFinding(t.TempDir(), func(*finding.Finding) { t.Error("a finding in an empty dir") }); err != nil {
		t.Fatal(err)
	}
	writeText(t, filepath.Join(run, "findings.json.gz"), "not gzip")
	if err := EachFinding(run, func(*finding.Finding) {}); err == nil {
		t.Fatal("corrupt file: want an error")
	}
}

// Runs before 0.5 stored what a health module could not read as raw keys; reading them gives the plain words.
func TestReadUpgradesDeniedKeys(t *testing.T) {
	dir := t.TempDir()
	old := f(t, map[string]any{"kind": "health", "module": "health", "id": "limited", "title": "cannot read: denied.shadow, denied.keys",
		"msg": "health.limited", "args": map[string]any{"what": "denied.shadow, sudo, denied.keys"}})
	plain := f(t, map[string]any{"kind": "health", "module": "health", "id": "limited2", "title": "cannot read: logs",
		"msg": "health.limited", "args": map[string]any{"what": "logs"}})
	noWhat := f(t, map[string]any{"kind": "health", "module": "health", "id": "limited3", "title": "t", "msg": "health.limited"})
	must(t, WriteHostFindings(dir, "web-01", []finding.Finding{old, plain, noWhat}))
	want := i18n.Msg("denied.title", map[string]any{"what_keys": []string{"denied.shadow", "denied.keys"}})
	check := func(how string, got []finding.Finding) {
		t.Helper()
		if len(got) != 3 {
			t.Fatalf("%s: %d findings", how, len(got))
		}
		if got[0].Msg != "denied.title" || got[0].Title != want.Text || !reflect.DeepEqual(got[0].Args["what_keys"], []string{"denied.shadow", "denied.keys"}) {
			t.Errorf("%s: upgraded %+v", how, got[0])
		}
		if got[1].Msg != "health.limited" || got[1].Title != "cannot read: logs" {
			t.Errorf("%s: no denied keys: unchanged %+v", how, got[1])
		}
		if got[2].Msg != "health.limited" || got[2].Title != "t" {
			t.Errorf("%s: no args: unchanged %+v", how, got[2])
		}
	}
	loaded, err := LoadFindings(dir)
	must(t, err)
	check("LoadFindings", loaded)
	var each []finding.Finding
	must(t, EachFinding(dir, func(f *finding.Finding) { each = append(each, *f) }))
	check("EachFinding", each)
}

func TestSplitLegacy(t *testing.T) {
	newRun := func(t *testing.T) string {
		env := filepath.Join(t.TempDir(), "e")
		fs := []finding.Finding{f(t, map[string]any{"host": "a", "id": "CVE-A"}), f(t, map[string]any{"host": "b", "id": "CVE-B"}),
			f(t, map[string]any{"host": "a", "id": "CVE-A2"})}
		writeRun(t, env, "2026-11-01_100000", fs, nil, nil, nil, nil)
		return filepath.Join(env, "2026-11-01_100000")
	}
	unsplit := func(t *testing.T, run string) {
		t.Helper()
		if legacyFile(run) == "" {
			t.Error("the single file is gone after a failed split")
		}
		for _, h := range []string{"a", "b"} {
			if exists(hostFindingsPath(run, h)) {
				t.Errorf("host file of %s in place after a failed split", h)
			}
			if l := tmpFiles(t, filepath.Join(run, "hosts", h)); l != nil {
				t.Errorf("temporary files left in %s: %v", h, l)
			}
		}
		fs, err := LoadFindings(run)
		must(t, err)
		if len(fs) != 3 {
			t.Errorf("findings after a failed split: %v", ids(fs))
		}
	}

	t.Run("splits and drops stale files", func(t *testing.T) {
		run := newRun(t)
		must(t, WriteHostFindings(run, "c", []finding.Finding{f(t, map[string]any{"host": "c", "id": "CVE-OLD"})})) // an earlier split's
		must(t, splitLegacy(run))
		if legacyFile(run) != "" {
			t.Fatal("single file left")
		}
		hfs, err := HostFiles(run)
		must(t, err)
		var got []string
		for _, hf := range hfs {
			got = append(got, hf.Host+":"+strings.Join(readIDs(t, hf.Path), ","))
		}
		if !slices.Equal(got, []string{"a:a/CVE-A,a/CVE-A2", "b:b/CVE-B"}) {
			t.Fatalf("split %v", got)
		}
		must(t, splitLegacy(run)) // nothing left to split
	})
	t.Run("host dir blocked", func(t *testing.T) {
		run := newRun(t)
		writeText(t, filepath.Join(run, "hosts", "b"), "x") // b's findings cannot be written
		if err := splitLegacy(run); err == nil {
			t.Fatal("want an error")
		}
		if legacyFile(run) == "" || exists(hostFindingsPath(run, "a")) || tmpFiles(t, filepath.Join(run, "hosts", "a")) != nil {
			t.Fatal("a's file written, or the single file gone")
		}
	})
	t.Run("stale file cannot go", func(t *testing.T) {
		run := newRun(t)
		blockWith(t, hostFindingsPath(run, "c"))
		if err := splitLegacy(run); err == nil {
			t.Fatal("want an error")
		}
		unsplit(t, run)
	})
	t.Run("commit", func(t *testing.T) {
		run := newRun(t)
		swap(t, &rename, func(string, string) error { return errBoom })
		if err := splitLegacy(run); !errors.Is(err, errBoom) {
			t.Fatalf("got %v", err)
		}
		unsplit(t, run)
	})
	t.Run("corrupt", func(t *testing.T) {
		run := newRun(t)
		writeText(t, filepath.Join(run, "findings.json.gz"), "not gzip")
		if err := MigrateEnv(filepath.Dir(run)); err == nil || !strings.Contains(err.Error(), run) {
			t.Fatalf("MigrateEnv names the run: %v", err)
		}
	})
}

func TestLinkOrCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	writeText(t, src, "data")

	dst := filepath.Join(dir, "a", "dst")
	must(t, linkOrCopy(src, dst))
	same := func(p string) bool {
		a, _ := os.Stat(src)
		b, err := os.Stat(p)
		must(t, err)
		return os.SameFile(a, b)
	}
	if !same(dst) {
		t.Fatal("not a hard link")
	}

	// the link cannot be made (its temporary name is taken): a copy
	dst2 := filepath.Join(dir, "b", "dst")
	blockWith(t, filepath.Join(dir, "b", ".dst.link"))
	must(t, linkOrCopy(src, dst2))
	if b, _ := os.ReadFile(dst2); string(b) != "data" || same(dst2) {
		t.Fatalf("copy %q, linked %v", b, same(dst2))
	}

	// the link cannot be put in place: the temporary link goes
	swap(t, &rename, func(string, string) error { return errBoom })
	if err := linkOrCopy(src, filepath.Join(dir, "c", "dst")); !errors.Is(err, errBoom) {
		t.Fatalf("got %v", err)
	}
	if exists(filepath.Join(dir, "c", ".dst.link")) {
		t.Fatal("temporary link left")
	}

	if err := linkOrCopy(src, filepath.Join(src, "dst")); err == nil {
		t.Fatal("parent is a file: want an error")
	}
}
