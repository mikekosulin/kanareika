package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// TestGenerate: a valid working directory: the org loads, every day has a full run with counts, current/ is
// merged, and the feeds are there; the same data every time.
func TestGenerate(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	out := filepath.Join(t.TempDir(), "demo")
	last := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	if err := generate(out, last, 6); err != nil {
		t.Fatal(err)
	}
	l, err := config.NewLoader(config.PathsAt(out))
	if err != nil {
		t.Fatal(err)
	}
	if _, errs := l.LoadAll(); len(errs) > 0 {
		t.Fatal(errs)
	}
	env := filepath.Join(out, "reports", "acme", "production")
	runs, _ := filepath.Glob(filepath.Join(env, "2026-*"))
	if len(runs) != 6 {
		t.Fatalf("%d runs", len(runs))
	}
	m, err := report.LoadMeta(runs[5])
	if err != nil || m.PlanCounts == nil || m.PlanCounts.P1+m.PlanCounts.P2+m.PlanCounts.P3 == 0 || m.HostsOK != 118 {
		t.Fatalf("%+v %v", m, err)
	}
	for _, f := range []string{"reports/acme/production/current/run.json", "reports/acme/staging/current/run.json", "feeds/kev.json",
		"feeds/epss.json", "feeds/updated", "reports/acme/production/2026-11-08_030000/hosts/web-01/access.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatal(err)
		}
	}
	// what the fleet is for: one CVE on dozens of hosts and under several package names, one update closing
	// several CVEs, images in docker and k8s
	fs, err := report.LoadFindings(runs[5])
	if err != nil {
		t.Fatal(err)
	}
	hostsOf, pkgsOf, cvesOf := map[string]map[string]bool{}, map[string]map[string]bool{}, map[string]map[string]bool{}
	add := func(m map[string]map[string]bool, k, v string) {
		if m[k] == nil {
			m[k] = map[string]bool{}
		}
		m[k][v] = true
	}
	docker, k8s := 0, 0
	for _, f := range fs {
		if f.Kind != "vuln" {
			continue
		}
		add(hostsOf, f.ID, f.Host)
		add(pkgsOf, f.ID, f.Pkg)
		add(cvesOf, f.Pkg+" "+f.Fixed, f.ID)
		switch f.Module {
		case "docker":
			docker++
		case "k8s":
			if f.Image == "" || f.Host != "k8s:prod-eu" {
				t.Fatalf("k8s finding without its image or cluster: %+v", f)
			}
			k8s++
		}
		if f.FirstSeen == "" || f.Published == "" || f.CVSSScore == nil {
			t.Fatalf("no clock or advisory facts: %+v", f)
		}
	}
	wide, multi, bundle := 0, 0, 0
	for id := range hostsOf {
		if len(hostsOf[id]) >= 20 {
			wide++
		}
		if len(pkgsOf[id]) >= 2 {
			multi++
		}
	}
	for _, ids := range cvesOf {
		if len(ids) >= 2 {
			bundle++
		}
	}
	if wide == 0 || multi == 0 || bundle == 0 || docker == 0 || k8s == 0 {
		t.Fatalf("wide %d, multi-package %d, bundles %d, docker %d, k8s %d", wide, multi, bundle, docker, k8s)
	}
	m4, _ := report.LoadMeta(runs[4])
	if m4.HostsFailed.Len() != 1 { // cache-01 is flaky on day 4
		t.Fatalf("%+v", m4.HostsFailed)
	}

	again := filepath.Join(t.TempDir(), "demo")
	if err := generate(again, last, 6); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(runs[5], "run.json"))
	b, _ := os.ReadFile(filepath.Join(again, "reports", "acme", "production", "2026-11-08_030000", "run.json"))
	if len(a) == 0 || len(a) != len(b) {
		t.Fatal("not the same data")
	}
	if err := generate(out, last, 6); err == nil {
		t.Fatal("wrote into a non-empty directory")
	}
}

// TestPasswordAuthFixed: over a longer month the exposed hosts allow passwords at first, and the finding is gone
// in the last six days.
func TestPasswordAuthFixed(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	out := filepath.Join(t.TempDir(), "demo")
	if err := generate(out, time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC), 8); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(out, "reports", "acme", "production")
	has := func(run string) bool {
		_, fs, err := report.LoadRun(filepath.Join(env, run))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			if f.ID == "ssh-password-auth" && f.Host == "web-01" {
				return true
			}
		}
		return false
	}
	if !has("2026-11-01_030000") || has("2026-11-08_030000") {
		t.Fatal("ssh-password-auth not on day 0 or still on the last day")
	}
}

// TestGenerateErrors: whatever fails midway is reported, not swallowed.
func TestGenerateErrors(t *testing.T) {
	boom := errors.New("boom")
	failMkdir := func(suffix string) func(string, os.FileMode) error {
		return func(p string, m os.FileMode) error {
			if strings.HasSuffix(p, suffix) {
				return boom
			}
			return os.MkdirAll(p, m)
		}
	}
	failWrite := func(suffix string) func(string, []byte, os.FileMode) error {
		return func(p string, b []byte, m os.FileMode) error {
			if strings.HasSuffix(p, suffix) {
				return boom
			}
			return os.WriteFile(p, b, m)
		}
	}
	cases := []struct {
		name string
		set  func()
		want string
	}{
		{"mkdir orgs", func() { mkdirAll = failMkdir("orgs") }, "boom"},
		{"mkdir run", func() { mkdirAll = failMkdir("_030000") }, "boom"},
		{"mkdir host", func() { mkdirAll = failMkdir("web-01") }, "boom"},
		{"org file", func() { writeFile = failWrite("acme.yml") }, "boom"},
		{"kev", func() { writeFile = failWrite("kev.json") }, "boom"},
		{"epss", func() { writeFile = failWrite("epss.json") }, "boom"},
		{"updated", func() { writeFile = failWrite("updated") }, "boom"},
		{"trivy cache", func() { writeFile = failWrite("metadata.json") }, "boom"},
		{"host file", func() { writeFile = failWrite("access.json") }, "boom"},
		{"bad org", func() {
			writeFile = func(p string, b []byte, m os.FileMode) error {
				if strings.HasSuffix(p, "acme.yml") {
					b = []byte("org: {}\n")
				}
				return os.WriteFile(p, b, m)
			}
		}, "demo org:"},
		{"loader", func() { newLoader = func(config.Paths) (*config.Loader, error) { return nil, boom } }, "boom"},
		{"policy", func() { loadPolicy = func(config.Paths) (*priority.Policy, error) { return nil, boom } }, "boom"},
		{"current", func() { updateCurrent = func(string, bool, bool) (string, error) { return "", boom } }, "boom"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			restore(t)
			t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
			c.set()
			err := generate(filepath.Join(t.TempDir(), "demo"), time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC), 2)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, want %q", err, c.want)
			}
		})
	}
	if err := writeJSON(filepath.Join(t.TempDir(), "x.json"), make(chan int)); err == nil {
		t.Fatal("a channel written as JSON")
	}
}

// restore puts the seams back after the test.
func restore(t *testing.T) {
	m, w, l, p, u, f := mkdirAll, writeFile, newLoader, loadPolicy, updateCurrent, fatal
	t.Cleanup(func() { mkdirAll, writeFile, newLoader, loadPolicy, updateCurrent, fatal = m, w, l, p, u, f })
}

type fatalErr string

// runMain runs main with these arguments; a fatal error comes back as a string.
func runMain(t *testing.T, args ...string) (stdout, fatalMsg string) {
	t.Helper()
	restore(t)
	oldArgs, oldFlags, oldOut := os.Args, flag.CommandLine, os.Stdout
	t.Cleanup(func() { os.Args, flag.CommandLine, os.Stdout = oldArgs, oldFlags, oldOut })
	os.Args = append([]string{"demo"}, args...)
	flag.CommandLine = flag.NewFlagSet("demo", flag.ContinueOnError)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fatal = func(v ...any) { panic(fatalErr(fmt.Sprint(v...))) }
	func() {
		defer func() {
			if e, ok := recover().(fatalErr); ok {
				fatalMsg = string(e)
			}
		}()
		main()
	}()
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b), fatalMsg
}

func TestMainFunc(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	out := filepath.Join(t.TempDir(), "demo")
	stdout, msg := runMain(t, "-out", out, "-end", "2026-11-08", "-days", "2")
	if msg != "" || !strings.Contains(stdout, "demo data in "+out) || !strings.Contains(stdout, "KANAREIKA_FEEDS_DIR="+filepath.Join(out, "feeds")) {
		t.Fatalf("%q %q", stdout, msg)
	}
	if _, err := os.Stat(filepath.Join(out, "reports", "acme", "staging", "2026-11-08_030000", "run.json")); err != nil {
		t.Fatal(err)
	}
	if _, msg := runMain(t, "-out", out, "-end", "yesterday"); !strings.Contains(msg, "cannot parse") {
		t.Fatalf("bad -end: %q", msg)
	}
	if _, msg := runMain(t, "-out", out, "-end", "2026-11-08"); !strings.Contains(msg, "is not empty") {
		t.Fatalf("non-empty -out: %q", msg)
	}
}

// TestTrivyCache: the demo's trivy cache reads as a DB built that morning and current until the evening.
func TestTrivyCache(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	out := filepath.Join(t.TempDir(), "demo")
	last := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	if err := generate(out, last, 2); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRIVY_CACHE_DIR", filepath.Join(out, "trivy"))
	dbs := trivy.DBStatus()
	if len(dbs) != 2 {
		t.Fatal(dbs)
	}
	for _, d := range dbs {
		if !d.Updated.Equal(last.Add(6*time.Hour)) || d.Outdated(last.Add(12*time.Hour)) || !d.Outdated(last.Add(19*time.Hour)) {
			t.Errorf("%s: updated %v, next %v", d.Name, d.Updated, d.Next)
		}
	}
}
