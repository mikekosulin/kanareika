package trivy

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/jsonx"
)

type seen struct {
	target string
	v      Vulnerability
}

func readAll(t *testing.T, doc string, strs jsonx.Strings, meta any) ([]seen, error) {
	t.Helper()
	var out []seen
	err := ReadReport(strings.NewReader(doc), strs, meta, func(target string, v *Vulnerability) {
		out = append(out, seen{target, *v})
	})
	return out, err
}

// TestReadReport: Results in order with their targets, unknown members (nested or not) skipped, keys matched
// case-insensitively, the Metadata block decoded into meta, null and empty parts allowed.
func TestReadReport(t *testing.T) {
	doc := `{
  "SchemaVersion": 2,
  "ArtifactName": "web",
  "Extra": {"a": [1, {"b": [true, null, "x"]}], "c": {"d": {}}},
  "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}, "ImageID": "sha256:abc", "Junk": [1, 2]},
  "Results": [
    {"Target": "os", "Class": "os-pkgs", "Packages": [{"Name": "x"}], "Vulnerabilities": [
      {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "1.0", "FixedVersion": "1.1",
       "Status": "fixed", "Severity": "HIGH", "Title": "t", "DataSource": {"ID": "ubuntu", "URLs": ["u"]},
       "CweIDs": ["CWE-94"], "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N", "V3Score": 9.8}}},
      {"VulnerabilityID": "CVE-2", "PkgName": "zlib", "Title": "t"}
    ]},
    {"Target": "empty", "Vulnerabilities": []},
    {"Target": "none", "Vulnerabilities": null},
    {"Target": "absent"},
    null,
    {"vulnerabilities": [{"vulnerabilityid": "CVE-3", "PkgName": "early"}], "target": "lower", "Misc": [[], {}]}
  ],
  "Trailer": [1, 2, 3]
}`
	var meta struct {
		OS      struct{ Family, Name string }
		ImageID string
	}
	strs := jsonx.Strings{}
	got, err := readAll(t, doc, strs, &meta)
	must(t, err)
	if meta.OS.Family != "ubuntu" || meta.OS.Name != "22.04" || meta.ImageID != "sha256:abc" {
		t.Fatalf("metadata: %+v", meta)
	}
	if len(got) != 3 {
		t.Fatalf("%d vulnerabilities: %+v", len(got), got)
	}
	v := got[0].v
	if got[0].target != "os" || v.VulnerabilityID != "CVE-1" || v.PkgName != "openssl" || v.InstalledVersion != "1.0" ||
		v.FixedVersion != "1.1" || v.Status != "fixed" || v.Severity == nil || *v.Severity != "HIGH" ||
		!reflect.DeepEqual(v.CweIDs, []string{"CWE-94"}) || !reflect.DeepEqual(v.CVSS.Sources, []string{"nvd"}) ||
		v.CVSS.Vectors["nvd"].V3Score != 9.8 {
		t.Fatalf("first: %q %+v", got[0].target, v)
	}
	// v is reset between vulnerabilities: nothing of CVE-1 leaks into CVE-2
	if v2 := got[1].v; got[1].target != "os" || v2.VulnerabilityID != "CVE-2" || v2.Severity != nil ||
		v2.FixedVersion != "" || v2.CweIDs != nil || len(v2.CVSS.Sources) != 0 {
		t.Fatalf("second: %+v", v2)
	}
	// listed before its target: kept until the target comes
	if got[2].target != "lower" || got[2].v.VulnerabilityID != "CVE-3" || got[2].v.PkgName != "early" {
		t.Fatalf("early: %q %+v", got[2].target, got[2].v)
	}
	// strings interned in the caller's set: the same title is one copy
	if strs["openssl"] != "openssl" || unsafe.StringData(got[0].v.Title) != unsafe.StringData(got[1].v.Title) {
		t.Fatal("strings not interned")
	}

	// no meta: Metadata skipped, a nil set works
	got, err = readAll(t, doc, nil, nil)
	if err != nil || len(got) != 3 {
		t.Fatal(err, len(got))
	}
	for _, doc := range []string{`null`, `{}`, `{"Results":null}`, `{"Results":[]}`, `{"Metadata":{}}`} {
		if got, err := readAll(t, doc, nil, &meta); err != nil || len(got) != 0 {
			t.Errorf("%s: %v %v", doc, got, err)
		}
	}
}

// TestReadReportErrors: malformed or truncated JSON at every level is an error, prefixed, after the vulnerabilities
// read before it.
func TestReadReportErrors(t *testing.T) {
	for _, c := range []struct {
		doc  string
		want string // in the error
		n    int    // vulnerabilities delivered before it
	}{
		{``, "EOF", 0},
		{`[]`, "object expected", 0},
		{`"x"`, "object expected", 0},
		{`{"Results":{}}`, "array expected", 0},
		{`{"Results":[1]}`, "object expected", 0},
		{`{"Results":[{"Target":"a","Vulnerabilities":"x"}]}`, "array expected", 0},
		{`{"Results":[{"Vulnerabilities":{},"Target":"a"}]}`, "array expected", 0},
		{`{"Results":[{"Target":1}]}`, "", 0},
		{`{"Results":[{"Target":"a","Vulnerabilities":[{"VulnerabilityID":"C1"},1]}]}`, "", 1},
		{`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"C1"},{"PkgName":2}],"Target":"a"}]}`, "", 1},
		{`{"Metadata":[1]}`, "", 0},
		{`{"Metadata":{"OS":`, "", 0},
		{`{"Extra":[1,`, "", 0},
		{`{"Results":[`, "", 0},
		{`{"Results":[{"Target":"a","Vulnerabilities":[{"VulnerabilityID":"C1"}`, "", 1},
		{`{"Results":[{"Target":"a","Vulnerabilities":[{"VulnerabilityID":"C1"},`, "", 1},
		{`{"Results":[{"Target":"a"`, "", 0},
		{`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"C1"}]`, "", 0},
		{`{"Results":[]`, "", 0},
		{`{"Results":[] "x":1}`, "", 0},
		{`{"Results":[]}}`, "", 0}, // trailing garbage is not read: the report ends at its object
		{`{1:2}`, "", 0},
	} {
		got, err := readAll(t, c.doc, nil, &struct{ OS struct{ Family string } }{})
		if c.doc == `{"Results":[]}}` {
			if err != nil {
				t.Errorf("%s: %v", c.doc, err)
			}
			continue
		}
		if err == nil || !strings.HasPrefix(err.Error(), "trivy report: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.doc, err)
		}
		if len(got) != c.n {
			t.Errorf("%s: %d delivered, want %d", c.doc, len(got), c.n)
		}
	}
}

// TestReadReportTruncated: a stream cut anywhere before its end is an error, never a silent partial report.
func TestReadReportTruncated(t *testing.T) {
	doc := `{"Metadata":{"OS":{"Family":"alpine"}},"Results":[{"Target":"a","Vulnerabilities":[` +
		`{"VulnerabilityID":"C1","CVSS":{"nvd":{"V3Score":1}}},{"VulnerabilityID":"C2"}]},{"Target":"b"}]}`
	for i := range len(doc) {
		if _, err := readAll(t, doc[:i], nil, &struct{}{}); err == nil {
			t.Errorf("cut at %d (%q): no error", i, doc[:i])
		}
	}
	if got, err := readAll(t, doc, nil, nil); err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
}

// TestReadFindingsMatchesVulnFindings: the streaming reader gives the same findings as parsing the whole report,
// over the recorded real-world fixture.
func TestReadFindingsMatchesVulnFindings(t *testing.T) {
	f, err := os.Open("testdata/report.json.gz")
	must(t, err)
	defer f.Close()
	zr, err := gzip.NewReader(f)
	must(t, err)
	data, err := io.ReadAll(zr)
	must(t, err)
	r, err := ParseReport(data)
	must(t, err)
	for _, base := range []finding.Finding{{Org: "acme", Host: "h", Module: "os_packages", Target: "os"},
		{Module: "docker"}} {
		want := VulnFindings(r, base)
		got, err := ReadFindings(Bytes(data), base, nil)
		must(t, err)
		if len(want) == 0 || !reflect.DeepEqual(got, want) {
			t.Fatalf("%d findings, want %d", len(got), len(want))
		}
	}
}

// TestEachFinding: findings on top of base, the result's target unless base names one, the advisory facts worked
// out again when the same CVE comes with different data.
func TestEachFinding(t *testing.T) {
	doc := `{"Metadata":{"ImageID":"sha256:1"},"Results":[{"Target":"usr/lib/app.jar","Vulnerabilities":[
  {"VulnerabilityID":"CVE-9","PkgName":"a","PkgPath":"p/a.jar","InstalledVersion":"1","FixedVersion":"2",
   "Status":"fixed","Severity":"CRITICAL","Title":"T","Description":"  remote   code execution ",
   "PrimaryURL":"https://u","PublishedDate":"2025-01-02T03:04:05Z","CweIDs":["CWE-502"],
   "CVSS":{"nvd":{"V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","V3Score":9.8}}},
  {"VulnerabilityID":"CVE-9","PkgName":"b","Title":"T","Description":"  remote   code execution ",
   "PublishedDate":"2025-01-02T03:04:05Z","CweIDs":["CWE-502"],
   "CVSS":{"nvd":{"V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","V3Score":9.8}}},
  {"VulnerabilityID":"CVE-9","PkgName":"c","Title":"T","Description":"  remote   code execution ",
   "CweIDs":["CWE-502"],"CVSS":{"nvd":{"V3Vector":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","V3Score":7.8}}},
  {"VulnerabilityID":"CVE-10","PkgName":"d"}
]}]}`
	var meta struct{ ImageID string }
	base := finding.Finding{Org: "acme", Host: "h", Group: "g", Exposure: 2, Module: "java"}
	fs, err := ReadFindings(strings.NewReader(doc), base, &meta)
	must(t, err)
	if meta.ImageID != "sha256:1" || len(fs) != 4 || cap(fs) != len(fs) {
		t.Fatalf("meta %+v, %d findings (cap %d)", meta, len(fs), cap(fs))
	}
	a := fs[0]
	if a.Org != "acme" || a.Host != "h" || a.Group != "g" || a.Exposure != 2 || a.Module != "java" ||
		a.Kind != finding.Vuln || a.ID != "CVE-9" || a.Pkg != "a" || a.PkgPath != "p/a.jar" || a.Installed != "1" ||
		a.Fixed != "2" || a.Status != "fixed" || a.Severity != "CRITICAL" || a.Title != "T" || a.URL != "https://u" ||
		a.Target != "usr/lib/app.jar" || !a.Preauth || !a.RCE || a.CVSSScore == nil || *a.CVSSScore != 9.8 ||
		a.Description != "remote code execution" || a.Published != "2025-01-02" ||
		a.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("first: %+v", a)
	}
	// the same advisory on another package: the same facts, shared
	b := fs[1]
	if b.Pkg != "b" || b.Severity != "UNKNOWN" || b.Vector != a.Vector || !b.Preauth || !b.RCE ||
		b.CVSSScore != a.CVSSScore || unsafe.StringData(b.Description) != unsafe.StringData(a.Description) {
		t.Fatalf("second: %+v", b)
	}
	// a different CVSS for the same CVE: worked out again, not taken from the first
	c := fs[2]
	if c.Preauth || !c.RCE || c.CVSSScore == nil || *c.CVSSScore != 7.8 || c.Published != "" ||
		c.Vector != "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("third: %+v", c)
	}
	if d := fs[3]; d.ID != "CVE-10" || d.Vector != "" || d.CVSSScore != nil || d.RCE || d.Description != "" {
		t.Fatalf("fourth: %+v", d)
	}

	// base.Target replaces the result's; f is reused between calls
	var ptrs []*finding.Finding
	var targets []string
	must(t, EachFinding(strings.NewReader(doc), finding.Finding{Target: "image:web"}, nil, func(f *finding.Finding) {
		ptrs = append(ptrs, f)
		targets = append(targets, f.Target+"/"+f.Pkg)
	}))
	if !reflect.DeepEqual(targets, []string{"image:web/a", "image:web/b", "image:web/c", "image:web/d"}) ||
		ptrs[0] != ptrs[3] {
		t.Fatal(targets)
	}

	// a broken report: the findings read so far and the error
	fs, err = ReadFindings(strings.NewReader(`{"Results":[{"Target":"x","Vulnerabilities":[{"VulnerabilityID":"C1"},`),
		base, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "trivy report: ") || len(fs) != 1 || fs[0].ID != "C1" ||
		fs[0].Target != "x" {
		t.Fatal(fs, err)
	}
}

// TestRunReport: Run's reader streams the report trivy wrote into findings; closing it removes the raw output and
// leaves the .gz copy, which holds the same report.
func TestRunReport(t *testing.T) {
	report := `{"Metadata":{"ImageID":"sha256:9"},"Results":[{"Target":"os","Vulnerabilities":[{"VulnerabilityID":"CVE-7","PkgName":"bash","Severity":"LOW"}]}]}`
	t.Setenv("REPORT", report)
	fake(t, `while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done; printf '%s' "$REPORT" > "$out"`)
	out := filepath.Join(t.TempDir(), "trivy-img.json")
	rep, err := Run(context.Background(), []string{"image", "web"}, out, time.Minute)
	must(t, err)
	var meta struct{ ImageID string }
	fs, err := ReadFindings(rep, finding.Finding{Module: "docker"}, &meta)
	must(t, err)
	if len(fs) != 1 || fs[0].ID != "CVE-7" || fs[0].Pkg != "bash" || fs[0].Severity != "LOW" || fs[0].Target != "os" ||
		meta.ImageID != "sha256:9" {
		t.Fatal(fs, meta)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("the raw output goes only when the reader is closed:", err)
	}
	must(t, rep.Close())
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("raw output kept", err)
	}
	gz, err := os.Open(out + ".gz")
	must(t, err)
	defer gz.Close()
	zr, err := gzip.NewReader(gz)
	must(t, err)
	b, err := io.ReadAll(zr)
	must(t, err)
	if string(b) != report {
		t.Fatal(string(b))
	}
	// closing twice: the file is gone, so is the error
	if err := rep.Close(); err == nil {
		t.Fatal("second close")
	}

	// the .gz copy of a non-empty report cannot be made: an error, the raw file left for a look
	out2 := filepath.Join(t.TempDir(), "trivy-fs.json")
	must(t, os.Mkdir(out2+".gz", 0o755))
	if rep, err := Run(context.Background(), []string{"fs", "/"}, out2, time.Minute); err == nil || rep != nil {
		t.Fatal("gzip into a directory must fail", err)
	}
	if _, err := os.Stat(out2); err != nil {
		t.Fatal(err)
	}
}

// TestRunEmptyReport: an empty output file reads as an empty report, its .gz holds "{}".
func TestRunEmptyReport(t *testing.T) {
	fake(t, `while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done; : > "$out"`)
	out := filepath.Join(t.TempDir(), "o.json")
	rep, err := Run(context.Background(), []string{"fs"}, out, time.Minute)
	must(t, err)
	fs, err := ReadFindings(rep, finding.Finding{}, nil)
	if err != nil || len(fs) != 0 {
		t.Fatal(fs, err)
	}
	must(t, rep.Close())
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("raw output kept", err)
	}
	gz, err := os.Open(out + ".gz")
	must(t, err)
	defer gz.Close()
	zr, err := gzip.NewReader(gz)
	must(t, err)
	if b, _ := io.ReadAll(zr); string(b) != "{}" {
		t.Fatal(string(b))
	}
}

// TestRunWaitsForSlot: a run waiting for a free slot gives up with its context, without starting trivy.
func TestRunWaitsForSlot(t *testing.T) {
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("CALLS", calls)
	fake(t, `echo x >> "$CALLS"; exit 0`)
	t.Cleanup(func() { SetParallel(0) })
	SetParallel(1)
	rel, err := acquire(context.Background())
	must(t, err)
	defer rel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	rep, err := Run(ctx, []string{"fs"}, filepath.Join(t.TempDir(), "o.json"), time.Minute)
	if !errors.Is(err, context.DeadlineExceeded) || rep != nil {
		t.Fatal(rep, err)
	}
	if _, err := os.Stat(calls); !os.IsNotExist(err) {
		t.Fatal("trivy ran without a slot")
	}
}

func TestBytes(t *testing.T) {
	r := Bytes([]byte(`{"Results":[{"Target":"t","Vulnerabilities":[{"VulnerabilityID":"C"}]}]}`))
	got, err := ReadFindings(r, finding.Finding{}, nil)
	if err != nil || len(got) != 1 || got[0].ID != "C" || got[0].Target != "t" {
		t.Fatal(got, err)
	}
	must(t, r.Close())
	if b, err := io.ReadAll(r); err != nil || len(b) != 0 {
		t.Fatal("read once", string(b), err)
	}
}

// resetLazy: a clean cache, no failure memo, the scan logger restored after the test.
func resetLazy(t *testing.T) string {
	t.Helper()
	cache := t.TempDir()
	t.Setenv("TRIVY_CACHE_DIR", cache)
	t.Setenv("TRIVY_DB_REPOSITORY", "")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", "")
	failMu.Lock()
	failed = map[string]failure{}
	failMu.Unlock()
	old := prepLog.Load()
	t.Cleanup(func() {
		prepLog.Store(old)
		failMu.Lock()
		failed = map[string]failure{}
		failMu.Unlock()
	})
	return cache
}

// TestDownloadOnDemand: only the on-demand DBs (the Java DB) are downloaded; a failure is returned.
func TestDownloadOnDemand(t *testing.T) {
	ctx := context.Background()
	cache := resetLazy(t)
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("CALLS", calls)
	fake(t, `echo "$@" >> "$CALLS"; mkdir -p "$TRIVY_CACHE_DIR/java-db"
echo '{"DownloadedAt":"2026-11-01T00:00:00Z"}' > "$TRIVY_CACHE_DIR/java-db/metadata.json"`)
	must(t, DownloadOnDemand(ctx, nil))
	b, err := os.ReadFile(calls)
	must(t, err)
	if strings.Count(string(b), "\n") != 1 || !strings.Contains(string(b), "--download-java-db-only") ||
		strings.Contains(string(b), "--download-db-only") {
		t.Fatalf("calls:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(cache, "java-db", "metadata.json")); err != nil {
		t.Fatal(err)
	}

	resetLazy(t)
	fake(t, `echo "FATAL registry down" >&2; exit 1`)
	err = DownloadOnDemand(ctx, nil)
	var te *Error
	if !errors.As(err, &te) || !strings.Contains(te.Msg, "registry down") {
		t.Fatal(err)
	}

	t.Setenv("TRIVY_CACHE_DIR", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", "")
	if err := DownloadOnDemand(ctx, nil); err == nil || !strings.Contains(err.Error(), "no cache directory") {
		t.Fatal(err)
	}
}

// TestJavaDBDownloadFails: a run that meets .jar files and cannot get the Java DB says so in the scan log and
// fails with trivy's error, without running again.
func TestJavaDBDownloadFails(t *testing.T) {
	resetLazy(t)
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("CALLS", calls)
	prepared.Store(true)
	t.Cleanup(func() { prepared.Store(false) })
	var logs []string
	logf := func(f string, _ ...any) { logs = append(logs, f) }
	prepLog.Store(&logf)
	fake(t, `echo "$@" >> "$CALLS"
for a in "$@"; do [ "$a" = --download-java-db-only ] && { echo "FATAL java mirror down" >&2; exit 1; }; done
echo "FATAL Unable to initialize the Java DB: '--skip-java-db-update' cannot be specified on the first run" >&2; exit 1`)
	_, err := Run(context.Background(), []string{"fs", "jars"}, filepath.Join(t.TempDir(), "o.json"), time.Minute)
	var te *Error
	if !errors.As(err, &te) || !strings.Contains(te.Msg, "Unable to initialize the Java DB") {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(calls)
	// every mirror tried once, the scan not run again
	if strings.Count(string(b), "--download-java-db-only") != 3 || strings.Count(string(b), "--output") != 1 {
		t.Fatalf("calls:\n%s", b)
	}
	if len(logs) < 2 || !strings.Contains(logs[0], "found .jar files") || !strings.HasPrefix(logs[len(logs)-1], "WARNING") {
		t.Fatal(logs)
	}
}
