package cli

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/assets"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/priv"
	"github.com/mikekosulin/kanareika/internal/scan"
)

// home returns the sandbox's KANAREIKA_HOME.
func home() string { return os.Getenv("KANAREIKA_HOME") }

// exampleOrg: orgs/acme.yml from the committed example (fake addresses only).
func exampleOrg(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile("../../orgs/_example.yml")
	must(t, err)
	write(t, filepath.Join(home(), "orgs", "acme.yml"), string(b))
}

// fixtureOrg: the dashboard fixture: org acme (production + staging) with the runs of the report fixture.
func fixtureOrg(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile("../server/testdata/parity/org.yml")
	must(t, err)
	write(t, filepath.Join(home(), "orgs", "acme.yml"), string(b))
	src := "../report/testdata/fixture/env/acme-production"
	dst := filepath.Join(home(), "reports", "acme", "production")
	must(t, filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	}))
}

func TestInitAndOrgNew(t *testing.T) {
	sandbox(t)
	code, out, _ := cli(t, "init")
	if code != 0 || !strings.Contains(out, "working directory: "+home()) || strings.Contains(out, "--home") {
		t.Fatal(code, out)
	}
	for _, d := range []string{"orgs", "reports", "secrets"} {
		if st, err := os.Stat(filepath.Join(home(), d)); err != nil || !st.IsDir() {
			t.Fatal(d, err)
		}
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(home(), "secrets")); st.Mode().Perm() != 0o700 {
			t.Fatal(st.Mode())
		}
	}
	other := filepath.Join(t.TempDir(), "audit")
	if code, out, _ := cli(t, "init", other); code != 0 || !strings.Contains(out, "--home "+other) {
		t.Fatal(code, out)
	}
	if _, err := os.Stat(filepath.Join(other, "orgs")); err != nil {
		t.Fatal(err)
	}

	if code, _, errs := cli(t, "validate"); code != 1 || !strings.Contains(errs, "org new") {
		t.Fatal(code, errs)
	}
	code, out, _ = cli(t, "org", "new", "beta")
	if code != 0 || !strings.Contains(out, "kanareika validate beta") {
		t.Fatal(code, out)
	}
	b, err := os.ReadFile(filepath.Join(home(), "orgs", "beta.yml"))
	must(t, err)
	if strings.Contains(string(b), "__ORG_ID__") || !strings.Contains(string(b), "id: beta") {
		t.Fatal(string(b))
	}
	// consent dated today, valid a year: not the template's placeholder dates, which run out for everyone at once
	today := time.Now().UTC()
	if !strings.Contains(string(b), "signed: "+today.Format(time.DateOnly)) ||
		!strings.Contains(string(b), "valid_until: "+today.AddDate(1, 0, 0).Format(time.DateOnly)) ||
		strings.Contains(string(b), assets.OrgTemplateUntil) {
		t.Fatal("consent dates:", string(b))
	}
	if st, err := os.Stat(filepath.Join(home(), "secrets", "beta")); err != nil || !st.IsDir() {
		t.Fatal(err)
	}
	// the new file is valid as is
	if code, out, errs := cli(t, "validate", "beta"); code != 0 || !strings.HasPrefix(out, "ok  beta") {
		t.Fatal(code, out, errs)
	}
	if code, _, errs := cli(t, "org", "new", "beta"); code != 1 || !strings.Contains(errs, "already exists") {
		t.Fatal(code, errs)
	}
	for _, bad := range []string{"Beta", "-x", "a b", "../x", "_hidden"} {
		if code, _, errs := cli(t, "org", "new", "--", bad); code != 1 || !strings.Contains(errs, "only a-z") {
			t.Fatal(bad, code, errs)
		}
	}
	if code, _, _ := cli(t, "org", "new"); code != 1 {
		t.Fatal(code)
	}
}

func TestHomeFlag(t *testing.T) {
	sandbox(t)
	exampleOrg(t)
	elsewhere := t.TempDir()
	// --home wins over KANAREIKA_HOME
	if code, _, errs := cli(t, "--home", elsewhere, "validate"); code != 1 || !strings.Contains(errs, elsewhere) {
		t.Fatal(code, errs)
	}
	if code, out, _ := cli(t, "validate"); code != 0 || !strings.Contains(out, "ok  acme") {
		t.Fatal(code, out)
	}
	// neither: the current directory
	t.Setenv("KANAREIKA_HOME", "")
	t.Chdir(elsewhere)
	if code, _, errs := cli(t, "validate"); code != 1 || !strings.Contains(errs, "no orgs") {
		t.Fatal(code, errs)
	}
}

func TestValidateAndShow(t *testing.T) {
	sandbox(t)
	exampleOrg(t)
	for _, args := range [][]string{{"validate"}, {"validate", "acme"}, {"validate", "--org", "acme"}} {
		if code, out, _ := cli(t, args...); code != 0 || !strings.Contains(out, "ok  acme             hosts [default: ") {
			t.Fatal(args, code, out)
		}
	}
	if code, _, errs := cli(t, "validate", "nope"); code != 1 || !strings.Contains(errs, "unknown org 'nope' (known: acme)") {
		t.Fatal(code, errs)
	}
	code, out, _ := cli(t, "show", "acme")
	if code != 0 || !strings.Contains(out, `"web-01": {`) || !strings.Contains(out, `"port": 22`) {
		t.Fatal(code, out)
	}
	if code, _, errs := cli(t, "show"); code != 1 || !strings.Contains(errs, "specify an org") {
		t.Fatal(code, errs)
	}
	if code, _, _ := cli(t, "show", "nope"); code != 1 {
		t.Fatal(code)
	}
	// a broken file stops everything, with exit code 2
	write(t, filepath.Join(home(), "orgs", "broken.yml"), "org: [")
	if code, _, errs := cli(t, "validate"); code != 2 || !strings.Contains(errs, "validation failed") {
		t.Fatal(code, errs)
	}
	// a broken policy override is a config error
	must(t, os.Remove(filepath.Join(home(), "orgs", "broken.yml")))
	write(t, filepath.Join(home(), "policy", "profiles.yml"), "default: [")
	if code, _, errs := cli(t, "validate"); code != 2 || !strings.Contains(errs, "config error") {
		t.Fatal(code, errs)
	}
}

func TestMigrate(t *testing.T) {
	sandbox(t)
	exampleOrg(t)
	if code, out, errs := cli(t, "migrate"); code != 0 || out != "" || !strings.Contains(errs, "current format") {
		t.Fatal(code, out, errs)
	}
	old := filepath.Join(home(), "orgs", "old.yml")
	write(t, old, "version: 99\norg: {id: old}\n")
	if code, _, errs := cli(t, "migrate", old); code != 1 || !strings.Contains(errs, old) {
		t.Fatal(code, errs)
	}
}

func TestHelper(t *testing.T) {
	sandbox(t)
	code, out, _ := cli(t, "helper")
	if code != 0 || out != priv.RenderHelper("v9.9.9-test") {
		t.Fatal(code)
	}
	dst := filepath.Join(t.TempDir(), "kanareika-collect")
	code, out, errs := cli(t, "helper", "-o", dst)
	if code != 0 || out != "" || !strings.Contains(errs, dst) {
		t.Fatal(code, out, errs)
	}
	b, err := os.ReadFile(dst)
	must(t, err)
	if string(b) != priv.RenderHelper("v9.9.9-test") {
		t.Fatal("content")
	}
	if st, _ := os.Stat(dst); runtime.GOOS != "windows" && st.Mode().Perm() != 0o755 {
		t.Fatal(st.Mode())
	}
	if code, _, _ := cli(t, "helper", "-o", filepath.Join(dst, "not-a-dir", "x")); code != 1 {
		t.Fatal(code)
	}
	if !strings.Contains(func() string { _, o, _ := cli(t, "helper", "--help"); return o }(), priv.HelperPath) {
		t.Fatal("help names the install path")
	}
}

func TestScanArgs(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	type call struct {
		org, env string
		opt      scan.Options
	}
	var calls []call
	rc := 0
	old := runOrg
	t.Cleanup(func() { runOrg = old })
	runOrg = func(_ context.Context, s *scan.Scanner, o *config.Org, env string, opt scan.Options) int {
		if s.Paths.Home != home() {
			t.Fatal(s.Paths)
		}
		calls = append(calls, call{o.ID, env, opt})
		return rc
	}
	for _, c := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"scan"}, 1, "name an org"},
		{[]string{"scan", "acme", "--all"}, 1, "mutually exclusive"},
		{[]string{"scan", "--all", "--env", "production"}, 1, "exactly one org"},
		{[]string{"scan", "--host", "x", "--all"}, 1, "exactly one org"},
		{[]string{"scan", "acme", "--module", "nope"}, 2, "invalid --module"},
		{[]string{"scan", "nope"}, 1, "unknown org"},
		{[]string{"scan", "acme"}, 1, "several environments"},
		{[]string{"scan", "acme", "--env", "qa"}, 1, "unknown env"},
	} {
		if code, _, errs := cli(t, c.args...); code != c.code || !strings.Contains(errs, c.msg) {
			t.Errorf("%v: %d %q", c.args, code, errs)
		}
	}
	if len(calls) != 0 {
		t.Fatal(calls)
	}

	code, _, _ := cli(t, "scan", "acme", "--env", "production", "--host", "web-01", "--module", "os_packages",
		"--dry-run", "--offline", "--parallel", "2", "--ignore-window")
	if code != 0 || len(calls) != 1 {
		t.Fatal(code, calls)
	}
	o := calls[0].opt
	if calls[0].org != "acme" || calls[0].env != "production" || !slices.Equal(o.Hosts, []string{"web-01"}) ||
		!slices.Equal(o.Modules, []string{"os_packages"}) || !o.DryRun || !o.Offline || o.Parallel != 2 ||
		!o.IgnoreWindow || o.Version != "v9.9.9-test" {
		t.Fatalf("%+v", calls[0])
	}
	// --all: every env of every org; exit codes are combined
	calls, rc = nil, 1
	if code, _, _ := cli(t, "scan", "--all"); code != 1 || len(calls) != 2 || calls[0].env != "production" ||
		calls[1].env != "staging" {
		t.Fatal(code, calls)
	}
	// KANAREIKA_OFFLINE turns --offline on
	calls, rc = nil, 0
	t.Setenv("KANAREIKA_OFFLINE", "1")
	if code, _, _ := cli(t, "scan", "--org", "acme", "--env", "staging"); code != 0 || !calls[0].opt.Offline {
		t.Fatal(code, calls)
	}
}

// TestScanDryRun: the real scanner, connecting nowhere.
func TestScanDryRun(t *testing.T) {
	sandbox(t)
	exampleOrg(t)
	code, out, errs := cli(t, "scan", "acme", "--dry-run", "--ignore-window")
	if code != 0 || !strings.Contains(out, "== acme / default") || !strings.Contains(out, "web-01") {
		t.Fatal(code, out, errs)
	}
	if entries, _ := os.ReadDir(filepath.Join(home(), "reports", "acme")); len(entries) > 1 {
		t.Fatal("a dry run wrote runs:", entries)
	}
}

func TestHistoryDiffPrune(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	code, out, _ := cli(t, "history", "acme", "--env", "production")
	if code != 0 || !strings.Contains(out, "== acme / production") || !strings.Contains(out, "2026-11-02_110000") {
		t.Fatal(code, out)
	}
	if code, _, errs := cli(t, "history"); code != 1 || !strings.Contains(errs, "specify one org") {
		t.Fatal(code, errs)
	}
	if code, _, errs := cli(t, "history", "acme"); code != 1 || !strings.Contains(errs, "several environments") {
		t.Fatal(code, errs)
	}
	if code, _, _ := cli(t, "history", "nope"); code != 1 {
		t.Fatal(code)
	}

	code, out, _ = cli(t, "diff", "--org", "acme", "--env", "production")
	if code != 0 || !strings.Contains(out, "2026-11-02_100000 -> 2026-11-02_110000") || !strings.Contains(out, "NEW: ") ||
		!strings.Contains(out, "RESOLVED: ") {
		t.Fatal(code, out)
	}
	code, out, _ = cli(t, "diff", "acme", "--env", "production", "--from", "2026-11-01_100000", "--limit", "0")
	if code != 0 || !strings.Contains(out, "2026-11-01_100000 -> 2026-11-02_110000") || !strings.Contains(out, "more") {
		t.Fatal(code, out)
	}
	if code, _, errs := cli(t, "diff", "acme", "--env", "production", "--to", "nope"); code != 1 ||
		!strings.Contains(errs, "unknown run; available:") {
		t.Fatal(code, errs)
	}
	if code, _, errs := cli(t, "diff", "acme", "--env", "staging"); code != 1 || !strings.Contains(errs, "two runs") {
		t.Fatal(code, errs)
	}
	if code, _, _ := cli(t, "diff", "acme"); code != 1 {
		t.Fatal(code)
	}
	if code, _, _ := cli(t, "diff", "acme", "nope"); code != 1 {
		t.Fatal(code)
	}
	if code, _, _ := cli(t, "diff", "nope"); code != 1 {
		t.Fatal(code)
	}

	code, out, _ = cli(t, "prune", "acme", "--keep-full", "1", "--keep-partial", "0", "--dry-run")
	if code != 0 || !strings.Contains(out, "acme/production: would delete") || !strings.Contains(out, "acme/staging: would delete 0") {
		t.Fatal(code, out)
	}
	before, _ := os.ReadDir(filepath.Join(home(), "reports", "acme", "production"))
	code, out, _ = cli(t, "prune", "--keep-full", "1", "--keep-partial", "0")
	after, _ := os.ReadDir(filepath.Join(home(), "reports", "acme", "production"))
	if code != 0 || !strings.Contains(out, "acme/production: deleted") || len(after) >= len(before) {
		t.Fatal(code, out, len(before), len(after))
	}
	if code, _, _ := cli(t, "prune", "nope"); code != 1 {
		t.Fatal(code)
	}
}

func TestVersionAndMCP(t *testing.T) {
	sandbox(t)
	code, out, _ := cli(t, "version")
	if code != 0 || !strings.HasPrefix(out, "kanareika v9.9.9-test\ntrivy none (KANAREIKA_TRIVY)\ngo") {
		t.Fatal(code, out)
	}
	if _, out, _ := cli(t, "--version"); !strings.Contains(out, "v9.9.9-test") {
		t.Fatal(out)
	}
	code, out, _ = cliIn(t, `{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}`+"\n", "mcp")
	if code != 0 || !strings.Contains(out, `"id": 7`) || !strings.Contains(out, "v9.9.9-test") {
		t.Fatal(code, out)
	}
}

func TestUnknownCommand(t *testing.T) {
	sandbox(t)
	if code, _, errs := cli(t, "frobnicate"); code != 1 || !strings.HasPrefix(errs, "error: unknown command") {
		t.Fatal(code, errs)
	}
}
