package report

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

func TestFixKeyImages(t *testing.T) {
	for _, c := range []struct {
		kw   map[string]any
		want string
	}{
		{map[string]any{"module": "k8s", "target": "k8s:prod/default/deploy/web", "image": "nginx:1.25"}, "image:k8s:nginx:1.25"},
		{map[string]any{"module": "k8s", "target": "k8s:prod/default/deploy/web"}, "image:k8s:k8s:prod/default/deploy/web"},
		{map[string]any{"module": "docker", "target": "image:redis:7"}, "image:docker:redis:7"},
	} {
		x := f(t, c.kw)
		if k, kind := FixKey(&x); k != c.want || kind != FixImage {
			t.Errorf("%v: %s %s, want %s", c.kw, k, kind, c.want)
		}
	}
}

func TestTotals(t *testing.T) {
	fs := []finding.Finding{
		f(t, map[string]any{"host": "a", "id": "CVE-1", "priority": "P1"}),
		f(t, map[string]any{"host": "b", "id": "CVE-1", "priority": "P3"}),                // the same update on b
		f(t, map[string]any{"host": "a", "id": "CVE-2", "priority": "P2", "pkg": "bash"}), // another update
		f(t, map[string]any{"host": "b", "id": "CVE-3", "priority": "P4", "pkg": "zlib", "fixed": "", "fix_state": "vendor"}),
		f(t, map[string]any{"host": "a", "id": "CVE-4", "priority": "P2", "accepted": true}),
		f(t, map[string]any{"host": "b", "id": "CVE-5", "priority": "P2", "backported": true}),
		f(t, map[string]any{"host": "b", "id": "CVE-6", "backported": true}), // no priority: not actionable
		f(t, map[string]any{"host": "a", "kind": "inventory", "module": "packages", "id": "pkg-list", "fixed": "", "priority": "P4"}),
		f(t, map[string]any{"host": "a", "kind": "misconfig", "module": "access", "id": "ssh-root", "fixed": "", "priority": "P1"}),
	}
	got := TotalsOf(fs)
	want := Totals{Fixes: 4, P1: 2, P2: 1, P4: 1, NoFix: 1, CVEs: 3, Hosts: 2, Findings: 5, Accepted: 1, Backported: 1}
	if got != want {
		t.Fatalf("TotalsOf\n got %+v\nwant %+v", got, want)
	}
	if bp := got.ByPriority(); !reflect.DeepEqual(bp, map[string]int{"P1": 2, "P2": 1, "P3": 0, "P4": 1}) {
		t.Errorf("ByPriority %v", bp)
	}
	by := TotalsByHost(fs)
	wantBy := map[string]Totals{
		"a": {Fixes: 3, P1: 2, P2: 1, CVEs: 2, Hosts: 1, Findings: 3, Accepted: 1},
		"b": {Fixes: 2, P3: 1, P4: 1, NoFix: 1, CVEs: 2, Hosts: 1, Findings: 2, Backported: 1},
	}
	if !reflect.DeepEqual(by, wantBy) {
		t.Fatalf("TotalsByHost\n got %+v\nwant %+v", by, wantBy)
	}
	all, none := TotalsSeq(slices.Values([]*finding.Finding{&fs[0], &fs[1]}), false)
	if none != nil || all.Fixes != 1 || all.P1 != 1 || all.Hosts != 2 {
		t.Errorf("TotalsSeq without hosts: %+v %v", all, none)
	}
	if (TotalsOf(nil) != Totals{}) || len(TotalsByHost(nil)) != 0 {
		t.Error("no findings: zero totals")
	}
}

func TestHighestFix(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"", ""}, ""},
		{[]string{"1.9", "", "1.10", "1.2", "1.9"}, "1.10"},
		{[]string{"2.0-rc1"}, "2.0-rc1"},
	} {
		if got := HighestFix(c.in); got != c.want {
			t.Errorf("HighestFix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTopIDs(t *testing.T) {
	set := map[string]bool{}
	for _, id := range []string{"CVE-2020-1", "CVE-2024-3", "CVE-2021-9", "CVE-2023-1", "CVE-2019-5", "CVE-2024-1",
		"CVE-2022-2", "CVE-2018-1", "CVE-2024-2", "CVE-2017-7", "CVE-2016-1", "CVE-2025-1"} {
		set[id] = true
	}
	want := []string{"CVE-2025-1", "CVE-2024-3", "CVE-2024-2", "CVE-2024-1", "CVE-2023-1", "CVE-2022-2", "CVE-2021-9", "CVE-2020-1"}
	for range 20 { // map order varies: every order gives the same top
		if got := topIDs(set); !slices.Equal(got, want) || cap(got) != len(got) {
			t.Fatalf("topIDs %v", got)
		}
	}
	if got := topIDs(map[string]bool{"b": true, "a": true}); !slices.Equal(got, []string{"b", "a"}) {
		t.Fatalf("fewer than n: %v", got)
	}
}

func TestPlanCountsOfPriorities(t *testing.T) {
	var fs []finding.Finding
	for i, p := range []string{"P1", "P2", "P2", "P3", "P4"} {
		fs = append(fs, f(t, map[string]any{"pkg": "pkg" + itoa(i), "id": "CVE-" + itoa(i), "priority": p}))
	}
	fs = append(fs, f(t, map[string]any{"pkg": "pkg1", "id": "CVE-9", "priority": "P2"})) // a second CVE of pkg1
	if got := PlanCountsOf(PatchPlan(fs)); got != (PlanCounts{P1: 1, P2: 2, P3: 1, P4: 1, CVEs: 6}) {
		t.Fatalf("%+v", got)
	}
}

func TestWriteSummary(t *testing.T) {
	dir := t.TempDir()
	meta := &Meta{Org: "acme", Env: "production", RunID: "2026-11-01_100000", HostsScanned: []string{"web-01"}}
	fs := []finding.Finding{
		f(t, map[string]any{"id": "CVE-1", "priority": "P2"}),
		f(t, map[string]any{"pkg": "libxml2", "id": "CVE-2", "priority": "P3", "fixed": "2.9.13+dfsg-1ubuntu0.3+esm1",
			"fix_state": "vendor"}),
	}
	must(t, WriteSummary(dir, meta, fs))
	b := readFile(t, filepath.Join(dir, "summary.md"))
	if string(b) != Summary(meta, fs) {
		t.Fatal("summary.md is not Summary")
	}
	if !strings.Contains(string(b), "only in Ubuntu Pro (ESM)") || !strings.Contains(string(b), "| openssl |") {
		t.Fatalf("summary.md:\n%s", b)
	}
	if err := WriteSummary(filepath.Join(dir, "missing"), meta, fs); err == nil {
		t.Fatal("missing dir: want an error")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("dir created")
	}
}
