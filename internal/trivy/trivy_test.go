package trivy

import (
	"archive/tar"
	"bytes"
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
			if !reflect.DeepEqual(got[i], c.want[i]) {
				t.Errorf("%s: %+v\nwant %+v", name, got[i], c.want[i])
			}
		}
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

func TestAssetAndExtract(t *testing.T) {
	for _, c := range [][3]string{{"linux", "amd64", "trivy_0.75.0_Linux-64bit.tar.gz"},
		{"linux", "arm64", "trivy_0.75.0_Linux-ARM64.tar.gz"}, {"darwin", "arm64", "trivy_0.75.0_macOS-ARM64.tar.gz"},
		{"darwin", "amd64", "trivy_0.75.0_macOS-64bit.tar.gz"}} {
		if a, err := asset(c[0], c[1]); err != nil || a != c[2] {
			t.Error(c, a, err)
		}
	}
	if _, err := asset("windows", "amd64"); err == nil {
		t.Error("windows")
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range [][2]string{{"LICENSE", "text"}, {"contrib/trivy", "nope"}, {"trivy", "#!binary"}} {
		must(t, tw.WriteHeader(&tar.Header{Name: e[0], Mode: 0o644, Size: int64(len(e[1])), Typeflag: tar.TypeReg}))
		_, _ = tw.Write([]byte(e[1]))
	}
	must(t, tw.Close())
	must(t, zw.Close())
	dest := filepath.Join(t.TempDir(), "trivy-x")
	must(t, extract(&buf, dest))
	b, _ := os.ReadFile(dest)
	st, _ := os.Stat(dest)
	if string(b) != "#!binary" || st.Mode().Perm() != 0o755 {
		t.Fatal(string(b), st.Mode())
	}
}

// KANAREIKA_TEST_DOWNLOAD=1: really download the pinned release for this platform (network).
func TestInstallDownload(t *testing.T) {
	if os.Getenv("KANAREIKA_TEST_DOWNLOAD") == "" {
		t.Skip("set KANAREIKA_TEST_DOWNLOAD=1")
	}
	dest := filepath.Join(t.TempDir(), "trivy-"+Pinned)
	must(t, install(context.Background(), dest, runtime.GOOS, runtime.GOARCH))
	if v := versionOf(context.Background(), dest); v != Pinned {
		t.Fatal(v)
	}
}
