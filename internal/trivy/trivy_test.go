package trivy

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mikekosulin/kanareika/internal/finding"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// testdata/python.json: recorded with the former Python implementation over report.json.gz — vulnerabilities sampled from
// real trivy reports (OS SBOM scans of Ubuntu / CentOS 7 / CentOS Stream 9, images, filesystems; every CVSS source
// layout seen; descriptions cut to 620 characters, paths and targets anonymized) plus edge cases. Recorded once
// with the former Python implementation (removed from the repo; the Go port had to match it) and kept as a frozen
// fixture: a change here is a behaviour change — review it as such.
func TestMatchesPython(t *testing.T) {
	f, err := os.Open("testdata/report.json.gz")
	must(t, err)
	defer f.Close()
	zr, err := gzip.NewReader(f)
	must(t, err)
	data, err := io.ReadAll(zr)
	must(t, err)
	r, err := ParseReport(data)
	must(t, err)
	b, err := os.ReadFile("testdata/python.json")
	must(t, err)
	var g struct {
		Edge          []Vulnerability   `json:"edge"`
		Classify      []Class           `json:"classify"`
		FindingsOS    []finding.Finding `json:"findings_os"`
		FindingsImage []finding.Finding `json:"findings_image"`
	}
	must(t, json.Unmarshal(b, &g))
	r.Results = append(r.Results, Result{Target: "edge", Vulnerabilities: g.Edge}, Result{Target: "empty"},
		Result{Target: "none"})
	i := 0
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			if got := Classify(v); got != g.Classify[i] {
				t.Errorf("%s: %+v, want %+v", v.VulnerabilityID, got, g.Classify[i])
			}
			i++
		}
	}
	if i != len(g.Classify) {
		t.Fatalf("%d vulnerabilities, want %d", i, len(g.Classify))
	}
	base := finding.Finding{Org: "acme", Host: "h", Group: "g", Exposure: 2, Module: "os_packages", Target: "os"}
	for name, c := range map[string]struct {
		base finding.Finding
		want []finding.Finding
	}{"os": {base, g.FindingsOS}, "image": {finding.Finding{Module: "docker"}, g.FindingsImage}} {
		got := VulnFindings(r, c.base)
		if len(got) != len(c.want) {
			t.Fatalf("%s: %d findings, want %d", name, len(got), len(c.want))
		}
		for i := range got {
			// the frozen fixture predates the advisory facts (TestAdvisoryFacts covers them)
			g := got[i]
			g.Published, g.CVSSScore, g.Description = "", nil, ""
			if !reflect.DeepEqual(g, c.want[i]) {
				t.Errorf("%s: %+v\nwant %+v", name, g, c.want[i])
			}
		}
	}
}

// TestAdvisoryFacts: the publication date, the base score of the vector Classify reads, and the description,
// whitespace collapsed and cut at maxDescription runes with an ellipsis.
func TestAdvisoryFacts(t *testing.T) {
	r := &Report{Results: []Result{{Target: "os", Vulnerabilities: []Vulnerability{
		{VulnerabilityID: "CVE-0000-1", PublishedDate: "2024-03-11T15:15:00Z", Description: "Line one.\n\n  Line   two.",
			CVSS: CVSS{Sources: []string{"ghsa", "nvd"}, Vectors: map[string]Vectors{
				"ghsa": {V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", V3Score: 7.8},
				"nvd":  {V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8}}}},
		{VulnerabilityID: "CVE-0000-2", PublishedDate: "bad", Description: strings.Repeat("ü", 700),
			CVSS: CVSS{Sources: []string{"x"}, Vectors: map[string]Vectors{"x": {V40Vector: "CVSS:4.0/AV:N", V40Score: 6.1}}}},
		{VulnerabilityID: "CVE-0000-3", CVSS: CVSS{Sources: []string{"nvd"}, Vectors: map[string]Vectors{
			"nvd": {V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}},
		{VulnerabilityID: "CVE-0000-4"},
	}}}}
	fs := VulnFindings(r, finding.Finding{Target: "os"})
	if fs[0].Published != "2024-03-11" || fs[0].CVSSScore == nil || *fs[0].CVSSScore != 9.8 ||
		fs[0].Description != "Line one. Line two." {
		t.Errorf("nvd first, date only, whitespace collapsed: %+v", fs[0])
	}
	if fs[1].Published != "bad"[:0] || fs[1].CVSSScore == nil || *fs[1].CVSSScore != 6.1 ||
		utf8.RuneCountInString(fs[1].Description) != maxDescription || !strings.HasSuffix(fs[1].Description, "…") {
		t.Errorf("CVSS 4 score, a short date is dropped, long text cut: %q %v", fs[1].Published, fs[1].CVSSScore)
	}
	if fs[2].CVSSScore != nil || fs[3].CVSSScore != nil || fs[3].Description != "" || fs[3].Published != "" {
		t.Errorf("no score without one for the chosen vector, nothing invented: %+v %+v", fs[2], fs[3])
	}
}

func TestCVSSKeepsOrder(t *testing.T) {
	var v Vulnerability
	must(t, json.Unmarshal([]byte(`{"CVSS":{"julia":{"V3Vector":"J"},"bitnami":{"V3Vector":"B"}}}`), &v))
	if vector(v) != "J" || !reflect.DeepEqual(v.CVSS.Sources, []string{"julia", "bitnami"}) {
		t.Fatal(v.CVSS)
	}
	b, _ := json.Marshal(v.CVSS)
	if string(b) != `{"julia":{"V3Vector":"J","V40Vector":""},"bitnami":{"V3Vector":"B","V40Vector":""}}` {
		t.Fatal(string(b))
	}
}

// fake: a shell script standing in for trivy (KANAREIKA_TRIVY).
func fake(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
	p := filepath.Join(t.TempDir(), "trivy")
	must(t, os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755))
	t.Setenv("KANAREIKA_TRIVY", p)
}

// TestNoTelemetry: every trivy process runs with telemetry and the version check off, whatever the subcommand.
func TestNoTelemetry(t *testing.T) {
	env := filepath.Join(t.TempDir(), "env")
	fake(t, `env > `+env+`; while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done; echo '{}' > "$out"`)
	t.Setenv("TRIVY_DISABLE_TELEMETRY", "false") // a user's setting does not turn it back on
	if _, err := Run(context.Background(), []string{"k8s", "x"}, filepath.Join(t.TempDir(), "o.json"), time.Minute); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(env)
	must(t, err)
	got := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			got[k] = v // the last one wins, as in a process environment
		}
	}
	if got["TRIVY_DISABLE_TELEMETRY"] != "true" || got["TRIVY_SKIP_VERSION_CHECK"] != "true" {
		t.Fatalf("telemetry %q, version check %q", got["TRIVY_DISABLE_TELEMETRY"], got["TRIVY_SKIP_VERSION_CHECK"])
	}
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	// writes its arguments as the report: shows the command line and the gzip step
	fake(t, `while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done; echo '{"Results":[]}' > "$out"`)
	out := filepath.Join(t.TempDir(), "trivy-os.json")
	data, err := Run(ctx, []string{"sbom", "x"}, out, time.Minute)
	must(t, err)
	if strings.TrimSpace(string(data)) != `{"Results":[]}` {
		t.Fatal(string(data))
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("raw output kept")
	}
	if _, err := os.Stat(out + ".gz"); err != nil {
		t.Fatal(err)
	}

	fake(t, `echo noise >&2; echo "2026 FATAL boom" >&2; echo "x ERROR bad" >&2; exit 3`)
	_, err = Run(ctx, []string{"fs", "/x"}, out, time.Minute)
	var te *Error
	if !errors.As(err, &te) || te.Msg != "trivy fs: 2026 FATAL boom\nx ERROR bad" {
		t.Fatal(err)
	}
	fake(t, `exit 2`)
	if _, err = Run(ctx, []string{"fs"}, out, time.Minute); err == nil || err.Error() != "trivy fs: exit 2" {
		t.Fatal(err)
	}
	fake(t, `sleep 5`)
	if _, err = Run(ctx, []string{"fs"}, out, 100*time.Millisecond); err == nil || errors.As(err, &te) {
		t.Fatal("timeout must not be a trivy Error", err)
	}
	fake(t, `echo '{"Version":"0.75.0"}'`)
	if v := Version(ctx); v != "0.75.0" {
		t.Fatal(v)
	}
	fake(t, `exit 1`)
	if v := Version(ctx); v != "?" {
		t.Fatal(v)
	}
}

// TestPrepare: repositories tried in order until one works; overrides; the cached DB as the last resort.
func TestPrepare(t *testing.T) {
	ctx := context.Background()
	t.Setenv("TRIVY_CACHE_DIR", t.TempDir())
	t.Setenv("TRIVY_DB_REPOSITORY", "")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("CALLS", calls)
	// records the repository; ghcr.io fails, the rest work
	fake(t, `repo=-; while [ $# -gt 0 ]; do case $1 in --db-repository|--java-db-repository) repo=$2;; esac; shift; done
echo "$repo" >> "$CALLS"; case $repo in ghcr.io/*) echo "FATAL stream error" >&2; exit 1;; esac; exit 0`)
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, f) }

	must(t, Prepare(ctx, logf))
	got, _ := os.ReadFile(calls)
	want := "ghcr.io/aquasecurity/trivy-db:2\nmirror.gcr.io/aquasec/trivy-db:2\n" +
		"ghcr.io/aquasecurity/trivy-java-db:1\nmirror.gcr.io/aquasec/trivy-java-db:1\n"
	if string(got) != want {
		t.Fatalf("calls:\n%s", got)
	}
	if len(logs) != 2 {
		t.Fatal(logs)
	}

	// kanareika's override, then trivy's own setting (no repository flag at all)
	os.Remove(calls)
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", " my.registry/trivy-db:2 , ")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "x/java:1")
	must(t, Prepare(ctx, nil))
	if got, _ := os.ReadFile(calls); string(got) != "my.registry/trivy-db:2\n-\n" {
		t.Fatalf("calls:\n%s", got)
	}

	// nothing reachable: fails with every attempt listed, unless a DB is cached
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", "")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	fake(t, `echo "FATAL down" >&2; exit 1`)
	err := Prepare(ctx, nil)
	var te *Error
	if !errors.As(err, &te) || strings.Count(te.Msg, "FATAL down") != 3 || !strings.Contains(te.Msg, "public.ecr.aws/") {
		t.Fatal(err)
	}
	for _, d := range []string{"db", "java-db"} {
		p := filepath.Join(os.Getenv("TRIVY_CACHE_DIR"), d)
		must(t, os.MkdirAll(p, 0o755))
		must(t, os.WriteFile(filepath.Join(p, "metadata.json"), []byte(`{"UpdatedAt":"2026-11-01T19:08:08Z"}`), 0o644))
	}
	logs = nil
	must(t, Prepare(ctx, logf))
	if len(logs) != 8 || !strings.HasPrefix(logs[3], "WARNING") || !strings.HasPrefix(logs[7], "WARNING") {
		t.Fatal(logs)
	}
}
