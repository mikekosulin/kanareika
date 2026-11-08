package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/prompt"
	"github.com/mikekosulin/kanareika/internal/server"
	"github.com/mikekosulin/kanareika/internal/tui"
)

func TestExitErrorMessage(t *testing.T) {
	err := fail(4, "host %s down", "web-01")
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 4 || err.Error() != "host web-01 down" {
		t.Fatal(err)
	}
}

// TestHomeUnresolvable: the current directory is gone, so a relative path has no absolute one.
func TestHomeUnresolvable(t *testing.T) {
	sandbox(t)
	old := absPath
	t.Cleanup(func() { absPath = old })
	var asked []string
	absPath = func(p string) (string, error) {
		asked = append(asked, p)
		return "", errors.New("getwd: no such file or directory")
	}
	t.Setenv("KANAREIKA_HOME", "")
	if code, _, errs := cli(t, "validate"); code != 1 || errs != "error: getwd: no such file or directory\n" {
		t.Fatal(code, errs)
	}
	absPath = func(p string) (string, error) {
		asked = append(asked, p)
		if p == "audit" {
			return "", errors.New("getwd: gone")
		}
		return old(p)
	}
	if code, _, errs := cli(t, "init", "audit"); code != 1 || errs != "error: getwd: gone\n" {
		t.Fatal(code, errs)
	}
	if len(asked) != 3 || asked[0] != "." || asked[2] != "audit" {
		t.Fatal(asked)
	}
}

func TestWorkspaceErrors(t *testing.T) {
	sandbox(t)
	// secrets/ is a file: neither init nor org new can make the working directory
	write(t, filepath.Join(home(), "secrets"), "")
	if code, _, errs := cli(t, "init"); code != 1 || !strings.Contains(errs, "secrets") {
		t.Fatal(code, errs)
	}
	if code, _, errs := cli(t, "org", "new", "beta"); code != 1 || !strings.Contains(errs, "secrets") {
		t.Fatal(code, errs)
	}
	must(t, os.Remove(filepath.Join(home(), "secrets")))

	old := chmod
	t.Cleanup(func() { chmod = old })
	chmod = func(string, os.FileMode) error { return os.ErrPermission }
	if code, _, errs := cli(t, "init"); code != 1 || errs != "error: permission denied\n" {
		t.Fatal(code, errs)
	}
	chmod = old

	// secrets/<id> is a file: the org file is written, its secrets directory is not
	write(t, filepath.Join(home(), "secrets", "beta"), "")
	if code, _, errs := cli(t, "org", "new", "beta"); code != 1 || !strings.Contains(errs, errNotDir) {
		t.Fatal(code, errs)
	}
	// a name too long for the file system
	long := strings.Repeat("a", 300)
	if code, _, errs := cli(t, "org", "new", long); code != 1 || !strings.Contains(errs, long[:40]) { // the OS's own words
		t.Fatal(code, errs)
	}
}

// TestOrgNewWriteFails: the new org file cannot be written.
func TestOrgNewWriteFails(t *testing.T) {
	sandbox(t)
	ro := filepath.Join(t.TempDir(), "ro")
	write(t, ro, "")
	old := openFile
	t.Cleanup(func() { openFile = old })
	openFile = func(string, int, os.FileMode) (*os.File, error) { return os.Open(ro) } // read-only: Write fails
	if code, _, errs := cli(t, "org", "new", "beta"); code != 1 || !strings.HasPrefix(errs, "error: ") {
		t.Fatal(code, errs)
	}
	if _, err := os.Stat(filepath.Join(home(), "secrets", "beta")); !os.IsNotExist(err) {
		t.Fatal("secrets made after a failed write", err)
	}
}

func TestUnknownOrgWithoutOrgs(t *testing.T) {
	sandbox(t)
	code, _, errs := cli(t, "validate", "nope")
	if code != 1 || !strings.Contains(errs, "unknown org 'nope' (known: none: `kanareika org new <ORG_ID>` creates one)") {
		t.Fatal(code, errs)
	}
}

// TestOlderFormatNote: an org migrated in memory on load is pointed out, and the command goes on.
func TestOlderFormatNote(t *testing.T) {
	sandbox(t)
	exampleOrg(t)
	old := loadAll
	t.Cleanup(func() { loadAll = old })
	loadAll = func(l *config.Loader) ([]*config.Org, []string) {
		orgs, errs := l.LoadAll()
		for _, o := range orgs {
			o.Migrated = []string{"v2: colour -> color"}
		}
		return orgs, errs
	}
	code, out, errs := cli(t, "validate")
	want := "note: " + filepath.Join(home(), "orgs", "acme.yml") + " is in an older format (v2: colour -> color); `kanareika migrate` updates the file\n"
	if code != 0 || errs != want || !strings.Contains(out, "ok  acme") {
		t.Fatal(code, out, errs)
	}
}

func TestValidateOnlyNamedOrgs(t *testing.T) {
	sandbox(t)
	exampleOrg(t)
	if code, _, errs := cli(t, "org", "new", "beta"); code != 0 {
		t.Fatal(errs)
	}
	code, out, errs := cli(t, "validate", "beta")
	if code != 0 || !strings.HasPrefix(out, "ok  beta") || strings.Contains(out, "acme") {
		t.Fatal(code, out, errs)
	}
}

func TestMigrateReportsSteps(t *testing.T) {
	sandbox(t)
	exampleOrg(t)
	f := filepath.Join(home(), "orgs", "acme.yml")
	old := migrateFile
	t.Cleanup(func() { migrateFile = old })
	var dry []bool
	migrateFile = func(path string, dryRun bool) ([]string, error) {
		if path != f {
			t.Fatal(path)
		}
		dry = append(dry, dryRun)
		return []string{"v2: colour -> color", "v3: drop legacy"}, nil
	}
	code, out, errs := cli(t, "migrate", "--dry-run")
	if code != 0 || errs != "" || out != "would migrate "+f+":\n  - v2: colour -> color\n  - v3: drop legacy\n" {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, out, _ = cli(t, "migrate", f)
	if code != 0 || !strings.HasPrefix(out, "migrated "+f+":\n") || len(dry) != 2 || !dry[0] || dry[1] {
		t.Fatal(code, out, dry)
	}
}

func TestDBUpdateNoIPDB(t *testing.T) {
	sandbox(t)
	old := updateFeeds
	t.Cleanup(func() { updateFeeds = old })
	updateFeeds = func(context.Context, *priority.Policy) (priority.Stats, error) {
		return priority.Stats{KEV: 1, EPSS: 2}, nil
	}
	code, out, _ := cli(t, "db", "update", "--skip-trivy")
	if code != 0 || !strings.HasPrefix(out, "KEV: 1 CVEs, EPSS: 2 scores, IP DB (DB-IP Lite): city none, asn none -> ") {
		t.Fatal(code, out)
	}
}

// TestUpdateDBFunc: the update the interfaces start logs everything to one output.
func TestUpdateDBFunc(t *testing.T) {
	sandbox(t)
	fakeDownloads(t, nil, nil)
	a := &app{paths: config.PathsAt(home())}
	var out bytes.Buffer
	if err := a.updateDBFunc(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "KEV: 3 CVEs") || !strings.Contains(s, "trivy db: downloaded") ||
		!strings.Contains(s, "trivy db: 2026-11-05 19:01Z") {
		t.Fatal(s)
	}
}

func TestServerCannotStart(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	old := newServer
	t.Cleanup(func() { newServer = old })
	newServer = func(server.Options) (*server.Server, error) { return nil, errors.New("no page") }
	for _, args := range [][]string{{"web"}, {"tui"}} {
		if code, _, errs := cli(t, args...); code != 1 || errs != "error: no page\n" {
			t.Fatal(args, code, errs)
		}
	}
}

// TestRealServe: the default serveFunc listens, announces itself and stops with its context.
func TestRealServe(t *testing.T) {
	sandbox(t)
	s, err := server.New(server.Options{Paths: config.PathsAt(home()), Prompt: prompt.Build})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := serveFunc(ctx, s, "127.0.0.1", 0, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "kanareika dashboard on http://127.0.0.1:") {
		t.Fatal(out.String())
	}
}

// TestRealTUI: the default runTUI runs the program until Ctrl+C on its input.
func TestRealTUI(t *testing.T) {
	sandbox(t)
	if isTerminal() {
		t.Fatal("go test output is not a terminal")
	}
	s, err := server.New(server.Options{Paths: config.PathsAt(home()), Prompt: prompt.Build})
	must(t, err)
	m := tui.New(tui.Options{Client: tui.Local(s.Handler()), Settings: filepath.Join(t.TempDir(), "tui.json")})
	var out bytes.Buffer
	if err := runTUI(m, strings.NewReader("\x03"), &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		t.Fatal("nothing drawn")
	}
}

// stagingRuns: runs of acme/staging written by hand; broken has a run.json that is not JSON.
func stagingRuns(t *testing.T, broken bool) {
	t.Helper()
	dir := filepath.Join(home(), "reports", "acme", "staging")
	meta := func(id string) string {
		return `{"org":"acme","env":"staging","run_id":"` + id + `","selection":{"groups":[],"hosts":[],"modules":[]},` +
			`"hosts_scanned":["stg-01"],"hosts_ok":1,"hosts_failed":{},"module_errors":{}}`
	}
	write(t, filepath.Join(dir, "2026-11-03_100000", "run.json"), meta("2026-11-03_100000"))
	write(t, filepath.Join(dir, "2026-11-03_100000", "findings.json"), `[]`)
	write(t, filepath.Join(dir, "2026-11-04_100000", "run.json"), meta("2026-11-04_100000"))
	write(t, filepath.Join(dir, "2026-11-04_100000", "findings.json"), `[{"org":"acme","host":"stg-01","group":"stage",`+
		`"module":"os_packages","kind":"vuln","id":"CVE-2026-1000","pkg":"openssl","installed":"3.0.1","fixed":"3.0.2",`+
		`"status":"fixed","severity":"LOW","priority":null}]`)
	if broken {
		write(t, filepath.Join(dir, "2026-11-05_100000", "run.json"), "{")
	}
}

func TestDiffUnprioritized(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	stagingRuns(t, false)
	code, out, errs := cli(t, "diff", "acme", "--env", "staging")
	if code != 0 || !strings.Contains(out, "2026-11-03_100000 -> 2026-11-04_100000, comparing 1 hosts scanned in both") ||
		!strings.Contains(out, "NEW: 1\n  -   stg-01           CVE-2026-1000") {
		t.Fatal(code, out, errs)
	}
}

func TestBrokenRun(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	stagingRuns(t, true)
	for _, args := range [][]string{
		{"history", "acme", "--env", "staging"},
		{"diff", "acme", "--env", "staging", "--from", "2026-11-05_100000", "--to", "2026-11-04_100000"},
		{"diff", "acme", "--env", "staging", "--from", "2026-11-03_100000", "--to", "2026-11-05_100000"},
	} {
		if code, _, errs := cli(t, args...); code != 1 || !strings.HasPrefix(errs, "error: ") ||
			!strings.Contains(errs, "2026-11-05_100000/run.json: unexpected end of JSON input") {
			t.Errorf("%v: %d %q", args, code, errs)
		}
	}
}

func TestPruneSelectionAndErrors(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	if code, _, errs := cli(t, "org", "new", "beta"); code != 0 {
		t.Fatal(errs)
	}
	code, out, _ := cli(t, "prune", "beta", "--dry-run")
	if code != 0 || out != "beta/default: would delete 0\n" {
		t.Fatalf("%d %q", code, out)
	}
	// an environment directory that is a file
	must(t, os.MkdirAll(filepath.Join(home(), "reports", "beta"), 0o755))
	write(t, filepath.Join(home(), "reports", "beta", "default"), "")
	if code, _, errs := cli(t, "prune", "beta"); runtime.GOOS != "windows" && (code != 1 || !strings.Contains(errs, errNotDir)) {
		t.Fatal(code, errs) // Windows: a file there reads as no runs, not an error
	}
}
