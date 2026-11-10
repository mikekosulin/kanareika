package store

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/fset"
	"github.com/mikekosulin/kanareika/internal/report"
)

func writeFindings(t *testing.T, dir string, fs []finding.Finding) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "findings.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if err := json.NewEncoder(gz).Encode(fs); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func sample() []finding.Finding {
	s := func(v string) *string { return &v }
	x := func(v float64) *float64 { return &v }
	yes := true
	return []finding.Finding{
		{Org: "acme", Host: "web-01", Group: "web", Exposure: 1, Module: "os_packages", Kind: finding.Vuln, ID: "CVE-2024-0001",
			Pkg: "libssl3", SrcPkg: "openssl", Installed: "3.0.2-0ubuntu1.10", Fixed: "3.0.2-0ubuntu1.12", Status: "fixed",
			Severity: "HIGH", Title: "openssl: a flaw", URL: "https://example.com/CVE-2024-0001", Target: "os",
			Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Preauth: true, RCE: true, Kernel: true, Pending: true,
			FixState: finding.FixAvailable, RepoVersion: "3.0.2-0ubuntu1.12", KEV: true, EPSS: x(0.42), Priority: s("P1"),
			Due: s("2026-11-20"), FirstSeen: "2026-11-01", FixSince: "2026-11-02", ClockStart: "2026-11-01",
			DueWhy: finding.DueFirstSeen, Published: "2024-01-01", KEVDue: "2026-11-15", CVSSScore: x(9.8),
			Description: "A long description."},
		{Org: "acme", Host: "web-02", Group: "web", Module: "docker", Kind: finding.Vuln, ID: "CVE-2024-0001", Pkg: "libssl3",
			PkgPath: "usr/lib/x.so", Installed: "3.0.2", Target: "image:nginx:1.25", Image: "nginx:1.25", Inactive: true,
			Backported: true, ImageInUse: &yes, Title: "openssl: a flaw", Description: "A long description.", EPSS: x(0.42),
			Priority: s(""), Accepted: true, Exception: &finding.Exception{Reason: "lab", Owner: "alice", ReviewBy: "2027-01-01"}},
		{Org: "acme", Host: "web-01", Group: "web", Module: "hardening", Kind: finding.Misconfig, ID: "ssh-root-login",
			Title: "Root can log in over SSH", Msg: "ssh.root", Args: map[string]any{"port": 22.0, "keys": []any{"a", "b"}},
			Target: "/etc/ssh/sshd_config", TargetMsg: "file", TargetArgs: map[string]any{}, Priority: s("P3"),
			Extra: map[string]json.RawMessage{"future": json.RawMessage(`{"a":1}`)}},
		{Org: "acme", Host: "web-01", Kind: finding.Inventory, ID: "facts"},
	}
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	dir := filepath.Join(reports, "acme", "production", "current")
	writeFindings(t, dir, sample())
	want, err := report.LoadFindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Load(ctx, reports, dir) // imports
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(ctx, reports, dir) // from the database
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]*fset.Set{"imported": first, "loaded": second} {
		if got, err := d.Findings(); err != nil || !reflect.DeepEqual(got, want) {
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(want)
			t.Fatalf("%s:\n got %s\nwant %s", name, a, b)
		}
		for i := range want {
			if k, _ := report.FixKey(&want[i]); d.Items[i].U.Key != k {
				t.Fatalf("%s: unit %d = %q, want %q", name, i, d.Items[i].U.Key, k)
			}
		}
	}
}

// writeHosts writes fs as dir's host files (the layout of 0.6).
func writeHosts(t *testing.T, dir string, fs []finding.Finding) {
	t.Helper()
	by := map[string][]finding.Finding{}
	for _, f := range fs {
		by[report.FileHost(&f)] = append(by[report.FileHost(&f)], f)
	}
	for h, hf := range by {
		if err := report.WriteHostFindings(dir, h, hf); err != nil {
			t.Fatal(err)
		}
	}
}

func dirs(t *testing.T, ctx context.Context, reports string) (out []string) {
	t.Helper()
	db, err := Open(ctx, reports)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.NewSelect().Model((*Dataset)(nil)).ColumnExpr("DISTINCT dir").Order("dir").Scan(ctx, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHostFiles(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	run := filepath.Join(reports, "acme", "production", "2026-11-01_120000")
	writeHosts(t, run, sample())
	want, err := report.LoadFindings(run)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Load(ctx, reports, run)
	if err != nil || !reflect.DeepEqual(must(d.Findings()), want) {
		t.Fatalf("%v\n got %+v\nwant %+v", err, d, want)
	}
	// current/ links the run's files: their rows are copied
	cur := filepath.Join(reports, "acme", "production", "current")
	for _, h := range []string{"web-01", "web-02"} {
		dst := filepath.Join(cur, "hosts", h, "findings.json.gz")
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(run, "hosts", h, "findings.json.gz"), dst); err != nil {
			t.Skip("no hard links here")
		}
	}
	if err := Sync(ctx, reports, cur); err != nil {
		t.Fatal(err)
	}
	if d, err = Load(ctx, reports, cur); err != nil || !reflect.DeepEqual(must(d.Findings()), want) {
		t.Fatalf("current: %v %+v", err, d)
	}
	// a host scanned again: Sync takes only it again, the other host's rows stay
	one := sample()[1:2]
	one[0].Installed = "3.0.3"
	if err := os.Remove(filepath.Join(cur, "hosts", "web-02", "findings.json.gz")); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteHostFindings(cur, "web-02", one); err != nil {
		t.Fatal(err)
	}
	if err := Sync(ctx, reports, cur); err != nil {
		t.Fatal(err)
	}
	if d, err = Load(ctx, reports, cur); err != nil || d.Len() != 4 || d.Items[3].Installed != "3.0.3" {
		t.Fatalf("after SaveHost: %v %+v", err, d)
	}
	// a host's file gone: its rows go
	if err := os.RemoveAll(filepath.Join(cur, "hosts", "web-02")); err != nil {
		t.Fatal(err)
	}
	if d, err = Load(ctx, reports, cur); err != nil || d.Len() != 3 {
		t.Fatalf("after removal: %v %d", err, d.Len())
	}
}

func TestReimportAndPrune(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	dir := filepath.Join(reports, "acme", "production", "current")
	writeFindings(t, dir, sample())
	if _, err := Load(ctx, reports, dir); err != nil {
		t.Fatal(err)
	}
	// the file changes: imported again
	writeFindings(t, dir, sample()[:1])
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(dir, "findings.json.gz"), future, future); err != nil {
		t.Fatal(err)
	}
	d, err := Load(ctx, reports, dir)
	if err != nil || d.Len() != 1 {
		t.Fatalf("after a change: %v %d", err, d.Len())
	}
	// more runs than kept, and a removed directory: dropped
	var runs []string
	for i := range keepRuns + 2 {
		r := filepath.Join(reports, "acme", "production", "2026-11-0"+string(rune('1'+i))+"_120000")
		writeHosts(t, r, sample()[:2])
		if _, err := Load(ctx, reports, r); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, r)
	}
	if err := os.RemoveAll(runs[len(runs)-1]); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, reports, dir); err != nil {
		t.Fatal(err)
	}
	// the 8th run dropped the two oldest (keepRuns kept), then the newest went with its directory
	want := append(slices.Clone(runs[2:len(runs)-1]), dir)
	if got := dirs(t, ctx, reports); !reflect.DeepEqual(got, want) {
		t.Fatalf("kept %v, want %v", got, want)
	}
	db, err := Open(ctx, reports)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows int // keepRuns-1 runs of two hosts, current/'s single file: the rest went with their datasets
	if err := db.NewRaw("SELECT count(*) FROM packs").Scan(ctx, &rows); err != nil || rows != 2*(keepRuns-1)+1 {
		t.Fatalf("rows %d %v: cascade", rows, err)
	}
}

func TestNoFindingsFile(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	dir := filepath.Join(reports, "acme", "production", "current")
	d, err := Load(ctx, reports, dir)
	if err != nil || d.Len() != 0 {
		t.Fatalf("%v %+v", err, d)
	}
	if err := Sync(ctx, reports, dir); err != nil {
		t.Fatal(err)
	}
}

func TestOpenTwice(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	errs := make(chan error, 4)
	for range 4 {
		go func() {
			db, err := Open(ctx, reports)
			if err == nil {
				err = db.Close()
			}
			errs <- err
		}()
	}
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnreadableSchema(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	db, err := Open(ctx, reports)
	if err != nil {
		t.Fatal(err)
	}
	// a development build's schema: migrations applied, tables of another shape
	if _, err := db.ExecContext(ctx, "DROP TABLE packs; CREATE TABLE packs (x INTEGER)"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	dir := filepath.Join(reports, "acme", "production", "current")
	writeFindings(t, dir, sample())
	d, err := Load(ctx, reports, dir)
	if err != nil || d.Len() != len(sample()) {
		t.Fatalf("%v %v", err, d)
	}
}

func must(fs []finding.Finding, err error) []finding.Finding {
	if err != nil {
		panic(err)
	}
	return fs
}
