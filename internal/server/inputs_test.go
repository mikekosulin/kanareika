package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/tree"
)

func emptyView() *report.View { return &report.View{} }

// loadedInput: an input that has finished loading, with n findings.
func loadedInput(dir string, n int) *treeInput {
	in := &treeInput{dir: dir, n: n, ready: make(chan struct{})}
	close(in.ready)
	return in
}

// TestTrim: the most recent input always stays; the next ones while they fit in keepFindings, and no more than
// keepInputs; one still loading counts as nothing.
func TestTrim(t *testing.T) {
	big := loadedInput("big", keepFindings)
	small := func(d string) *treeInput { return loadedInput(d, 10) }
	loading := &treeInput{dir: "loading", ready: make(chan struct{})}
	for _, c := range []struct {
		name string
		ins  []*treeInput
		want []string
	}{
		{"one too big stays", []*treeInput{big, small("a")}, []string{"big"}},
		{"small ones up to keepInputs", []*treeInput{small("a"), small("b"), small("c"), small("d")}, []string{"a", "b", "c"}},
		{"loading counts nothing", []*treeInput{small("a"), loading, small("b")}, []string{"a", "loading", "b"}},
		{"past the budget", []*treeInput{small("a"), big}, []string{"a"}},
	} {
		got := trim(c.ins)
		var dirs []string
		for _, in := range got {
			dirs = append(dirs, in.dir)
		}
		if len(dirs) != len(c.want) {
			t.Errorf("%s: %v", c.name, dirs)
			continue
		}
		for i := range dirs {
			if dirs[i] != c.want[i] {
				t.Errorf("%s: %v", c.name, dirs)
			}
		}
		if cap(got) > len(got) && got[:cap(got)][len(got)] != nil {
			t.Errorf("%s: a trimmed input is still held by the array", c.name)
		}
	}
}

// TestLoadErrors: a view that isn't JSON and a reports directory without a database are errors of the load.
func TestLoadErrors(t *testing.T) {
	in := &treeInput{dir: t.TempDir()}
	if err := in.load(t.TempDir(), []byte("{")); err == nil {
		t.Fatal("a broken view loaded")
	}
	file := filepath.Join(t.TempDir(), "reports")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := in.load(file, []byte("{}")); err == nil {
		t.Fatal("loaded without a database")
	}
}

// TestPrebuild: the groupings are built ahead, each once; a server list of an org that is gone stops it quietly.
func TestPrebuild(t *testing.T) {
	s, _ := newTest(t, Options{})
	fs := []finding.Finding{{Org: "acme", Host: "web-01", Group: "web", Kind: finding.Vuln, ID: "CVE-1", Pkg: "openssl"}}
	in := loadedInput("x", 1)
	in.set, in.view = tree.NewSet(fs), emptyView()
	s.prebuild(query{"org": {"acme"}, "env": {"production"}}, in, "2026-11-10")
	if len(in.built) != 4 {
		t.Fatalf("%d trees built", len(in.built))
	}
	gone := loadedInput("y", 1)
	gone.set, gone.view = tree.NewSet(fs), emptyView()
	s.prebuild(query{"org": {"nope"}, "env": {"production"}}, gone, "2026-11-10")
	if len(gone.built) != 3 { // fix, CVE, server; the server list needs the org file
		t.Fatalf("%d trees built for a missing org", len(gone.built))
	}
}

// TestFailedHosts: a run lists the hosts it could not scan by name, sorted (what a retry scans again); none, no list.
func TestFailedHosts(t *testing.T) {
	if got := failedHosts(map[string]any{"hosts_failed": map[string]any{"web-02": "timeout", "db-01": "refused"}}); len(got) != 2 ||
		got[0] != "db-01" || got[1] != "web-02" {
		t.Fatalf("%v", got)
	}
	if got := failedHosts(map[string]any{"hosts_failed": map[string]any{}}); got != nil {
		t.Fatalf("%v", got)
	}
	if got := failedHosts(nil); got != nil {
		t.Fatalf("%v", got)
	}
}
