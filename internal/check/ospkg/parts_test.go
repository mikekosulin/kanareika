package ospkg

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/checktest"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/sbom"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// The recorded hosts matched in many small trivy runs (each kernel build alone) give the findings of one run, in
// the same order: trivy here answers each run with the recorded report cut to the run's BOM.
func TestPartsReadAsOne(t *testing.T) {
	here, _ := filepath.Abs("testdata")
	oldRun, oldSize := trivyRun, partSize
	t.Cleanup(func() { trivyRun, partSize = oldRun, oldSize })
	tested := 0
	for _, c := range checktest.LoadReplays(t) {
		e, ok := c.Trivy["trivy-os.json"]
		if !ok || e.File == nil || *e.File == "" || len(c.Runs) != 1 {
			continue
		}
		var report map[string]any
		if err := json.Unmarshal(gunzipFile(t, filepath.Join(here, *e.File)), &report); err != nil {
			t.Fatal(err)
		}
		runs, vulns := 0, 0
		trivyRun = func(_ context.Context, args []string, _ string, _ time.Duration) (io.ReadCloser, error) {
			runs++
			b, n := cutReport(t, report, args[len(args)-1])
			vulns += n
			return trivy.Bytes(b), nil
		}
		r := c.Runs[0]
		run := func(size int) []finding.Finding {
			partSize, runs, vulns = size, 0, 0
			ctx := &check.Ctx{Context: context.Background(), SSH: &checktest.FakeSSH{Here: here, Case: &c},
				RunDir: t.TempDir(), Log: func(string, ...any) {}}
			got, err := Run(ctx, checktest.HostOf(r.Host), r.Cfg, t.TempDir(), r.Facts)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			return got
		}
		whole := run(0)
		if want := countVulns(report); vulns != want || runs != 1 {
			t.Fatalf("%s: one run: %d runs, %d of %d vulnerabilities", c.Name, runs, vulns, want)
		}
		split := run(40)
		if runs < 3 {
			t.Fatalf("%s: %d runs, want several", c.Name, runs)
		}
		if !reflect.DeepEqual(whole, split) {
			t.Errorf("%s: %d findings in %d runs differ from %d in one", c.Name, len(split), runs, len(whole))
		}
		t.Logf("%s: %d findings, %d runs", c.Name, len(split), runs)
		tested++
	}
	if tested == 0 {
		t.Fatal("no cases")
	}
}

func TestParts(t *testing.T) {
	p := func(name, ver string) sbom.Package {
		return sbom.Package{Name: name, Version: ver, Release: "1", Arch: "x86_64"}
	}
	i686 := p("glibc", "2.34")
	i686.Arch = "i686"
	pkgs := []sbom.Package{p("zlib", "1"), p("kernel-core", "5.14.0-761"), p("glibc", "2.34"), p("bash", "5"),
		p("kernel-core", "5.14.0-325"), i686, p("openssl", "3"), p("kernel", "5.14.0-325")}
	got := parts(pkgs, 2)
	names := [][]string{}
	for _, g := range got {
		var n []string
		for _, q := range g {
			n = append(n, q.Name+"@"+q.Version+"."+q.Arch)
		}
		names = append(names, n)
	}
	want := [][]string{{"bash@5.x86_64"}, {"glibc@2.34.x86_64", "glibc@2.34.i686"}, {"kernel@5.14.0-325.x86_64"},
		{"kernel-core@5.14.0-325.x86_64"}, {"kernel-core@5.14.0-761.x86_64"}, {"openssl@3.x86_64", "zlib@1.x86_64"}}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("parts:\n got %v\nwant %v", names, want)
	}
	if got := parts(pkgs[:2], 0); len(got) != 1 || len(got[0]) != 2 || got[0][0].Name != "zlib" {
		t.Errorf("no split: %v", got)
	}
	if got := parts([]sbom.Package{p("zlib", "1"), p("bash", "5")}, 10); len(got) != 1 || got[0][0].Name != "zlib" {
		t.Errorf("one part keeps the host's order: %v", got)
	}
}

// cutReport: report with only the vulnerabilities of the packages in the BOM at bomPath, and how many those are.
func cutReport(t *testing.T, report map[string]any, bomPath string) ([]byte, int) {
	t.Helper()
	b, err := os.ReadFile(bomPath)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Components []struct {
			Type, Name string
			Version    string
		}
	}
	if err := json.Unmarshal(b, &bom); err != nil {
		t.Fatal(err)
	}
	in := map[string]bool{}
	for _, c := range bom.Components {
		if c.Type == "library" {
			in[c.Name+" "+c.Version] = true
		}
	}
	out := map[string]any{}
	for k, v := range report {
		out[k] = v
	}
	n := 0
	var results []any
	for _, r := range asList(report["Results"]) {
		rm := map[string]any{}
		for k, v := range r.(map[string]any) {
			rm[k] = v
		}
		var keep []any
		for _, v := range asList(rm["Vulnerabilities"]) {
			vm := v.(map[string]any)
			if in[vm["PkgName"].(string)+" "+vm["InstalledVersion"].(string)] {
				keep = append(keep, v)
			}
		}
		n += len(keep)
		rm["Vulnerabilities"] = keep
		results = append(results, rm)
	}
	out["Results"] = results
	j, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return j, n
}

func countVulns(report map[string]any) int {
	n := 0
	for _, r := range asList(report["Results"]) {
		n += len(asList(r.(map[string]any)["Vulnerabilities"]))
	}
	return n
}

func asList(v any) []any { l, _ := v.([]any); return l }

func gunzipFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
