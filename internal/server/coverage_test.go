package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/mikekosulin/kanareika/assets"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/report"
)

// fixtureHome: testHome plus the acme/production runs of internal/report's fixture.
func fixtureHome(t *testing.T) (config.Paths, string) {
	t.Helper()
	p := testHome(t)
	env := filepath.Join(p.Home, "reports", "acme", "production")
	must(t, copyDir("../report/testdata/fixture/env/acme-production", env))
	return p, env
}

func TestReloadBrokenProfiles(t *testing.T) {
	p := testHome(t)
	must(t, os.MkdirAll(p.Policy, 0o755))
	must(t, os.WriteFile(filepath.Join(p.Policy, "profiles.yml"), []byte("default: [unclosed\n"), 0o644))
	_, h := newTest(t, Options{Paths: p})
	r := do(h, "GET", "/api/orgs", nil, nil)
	var d struct {
		Orgs   []any    `json:"orgs"`
		Errors []string `json:"errors"`
	}
	must(t, json.Unmarshal([]byte(r.body), &d))
	if r.code != 200 || len(d.Orgs) != 0 || len(d.Errors) != 1 || !strings.Contains(d.Errors[0], "profiles.yml") {
		t.Fatal(r.code, r.body)
	}
}

func TestModulesExtra(t *testing.T) {
	c := config.Checks{
		"zz_custom": {"enabled": true}, "aa_custom": {"enabled": true}, "off_custom": {"enabled": false},
		config.HostModules[0]: {"enabled": true},
	}
	got := modules(c)
	want := []string{config.HostModules[0], "aa_custom", "zz_custom"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatal(got)
	}
}

func TestQueryHelpers(t *testing.T) {
	q := parseQS("ips=192.0.2.1,,192.0.2.2,192.0.2.3&blank=&nokey")
	if got := q.list("ips", 2); strings.Join(got, ",") != "192.0.2.1,192.0.2.2" {
		t.Fatal(got)
	}
	if _, ok := q["blank"]; ok {
		t.Fatal("blank value kept")
	}
	if _, err := decode([]byte(`{} {}`)); err == nil || err.Error() != "trailing data" {
		t.Fatal(err)
	}
	if v, err := decode([]byte(`{"n": 12345678901234567890}`)); err != nil || asMap(v)["n"].(json.Number).String() != "12345678901234567890" {
		t.Fatal(v, err)
	}
}

func TestRunsEdgeCases(t *testing.T) {
	env := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		must(t, os.MkdirAll(filepath.Dir(filepath.Join(env, rel)), 0o755))
		must(t, os.WriteFile(filepath.Join(env, rel), []byte(body), 0o644))
	}
	must(t, os.MkdirAll(filepath.Join(env, "2026-11-01_000000"), 0o755)) // nothing in it: skipped
	write("2026-11-01_000001/run.json", "{broken")                       // broken, no status: skipped
	write("2026-11-01_000002/run.json", `{"started": "s", "finished": "f", "hosts_scanned": ["web-01"]}`)
	write("2026-11-01_000002/status.json", `{"state": "running", "updated": "2026-11-01T00:00:00Z"}`)
	write("2026-11-01_000003/status.json", `{"state": "running", "updated": "not a time", "hosts": ["web-01", "web-02"]}`)
	rs := runs(env)
	if len(rs) != 2 {
		t.Fatalf("%+v", rs)
	}
	if rs[0].RunID != "2026-11-01_000002" || rs[0].State != "done" || rs[0].Started != "s" || rs[0].HostsTotal != 1 {
		t.Fatalf("finished run with a leftover status: %+v", rs[0])
	}
	if rs[1].State != "stale" || rs[1].HostsTotal != 2 {
		t.Fatalf("unparseable heartbeat: %+v", rs[1])
	}
	if age("2026-11-01 00:00:00Z") <= 0 || age(nil) != 1<<62 {
		t.Fatal("age")
	}
}

func TestStoredView(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "view.json")
	for _, c := range []struct {
		body    string
		current bool
		ok      bool
	}{
		{"{broken", false, false},
		{" null\n", true, false},
		{`{"version": 1}`, false, false},
		{`{"version": "11"}`, false, false},
		{`{"version": 11}`, false, true},
		{`{"version": 1}`, true, true},
	} {
		must(t, os.WriteFile(p, []byte(c.body), 0o644))
		b, ok := storedView(p, c.current)
		if ok != c.ok || ok && string(b) != c.body {
			t.Errorf("%q current=%v: %v", c.body, c.current, ok)
		}
	}
	if _, ok := storedView(filepath.Join(dir, "missing.json"), true); ok {
		t.Fatal("missing file usable")
	}
}

func TestViewCache(t *testing.T) {
	p, env := fixtureHome(t)
	s, h := newTest(t, Options{Paths: p})
	run := "2026-11-01_100000"
	path := "/api/run?org=acme&env=production&run=" + run
	first := do(h, "GET", path, nil, nil)
	if first.code != 200 {
		t.Fatal(first.code, first.body)
	}
	// the rebuilt view was stored, with plan_counts added to run.json
	if _, err := os.Stat(filepath.Join(env, run, "view.json")); err != nil {
		t.Fatal(err)
	}
	m, err := report.LoadMeta(filepath.Join(env, run))
	must(t, err)
	if m.PlanCounts == nil {
		t.Fatal("plan_counts not written")
	}
	for i := 0; i < 2; i++ {
		if r := do(h, "GET", path, nil, nil); r.code != 200 || r.body != first.body {
			t.Fatal(r.code)
		}
	}
	if len(s.views) != 2 { // built (no view.json yet), then read from view.json once, then served from the cache
		t.Fatal(len(s.views))
	}
	// the cache keeps the last nine views
	for i := 0; i < 12; i++ {
		d := filepath.Join(t.TempDir(), "run")
		must(t, os.MkdirAll(d, 0o755))
		body := `{"version": 11, "n": ` + string(rune('0'+i%10)) + `}`
		must(t, os.WriteFile(filepath.Join(d, "view.json"), []byte(body), 0o644))
		b, err := s.view(d)
		if err != nil || string(b) != body {
			t.Fatal(string(b), err)
		}
	}
	if len(s.views) != 9 {
		t.Fatal(len(s.views))
	}
}

func TestViewErrors(t *testing.T) {
	p, env := fixtureHome(t)
	var logged bytes.Buffer
	s, err := New(Options{Paths: p, Log: log.New(&logged, "", 0),
		Prompt: func(*config.Org, string, *report.View, []string, string) string { return "" }})
	must(t, err)
	h := s.Handler()

	// findings.json that does not decode: 500, logged
	bad := filepath.Join(env, "2026-11-01_110000")
	must(t, os.WriteFile(filepath.Join(bad, "findings.json"), []byte("not json"), 0o644))
	for _, path := range []string{"/api/run", "/api/prompt"} {
		if r := do(h, "GET", path+"?org=acme&env=production&run=2026-11-01_110000", nil, nil); r.code != 500 || r.body != `{"error": "internal error"}` {
			t.Fatal(path, r.code, r.body)
		}
	}
	if !strings.Contains(logged.String(), "-> 500") || strings.Contains(logged.String(), "-> 501") {
		t.Fatal(logged.String())
	}

	// an earlier run whose run.json is broken: the previous run can't be found
	must(t, os.WriteFile(filepath.Join(env, "2026-11-01_100000", "run.json"), []byte("{"), 0o644))
	if _, err := s.view(filepath.Join(env, "2026-11-02_100000")); err == nil {
		t.Fatal("previous run error swallowed")
	}

	// a view that can't be encoded
	marshalView = func(any) ([]byte, error) { return nil, errors.New("encode failed") }
	t.Cleanup(func() { marshalView = defaultMarshalView })
	if _, err := s.view(filepath.Join(env, "2026-11-02_110000")); err == nil || err.Error() != "encode failed" {
		t.Fatal(err)
	}
}

var defaultMarshalView = marshalView

func TestCurrentUpdateError(t *testing.T) {
	p := testHome(t)
	must(t, os.MkdirAll(filepath.Join(p.Home, "reports", "acme"), 0o755))
	// the env dir is a file: current/ can't be locked or written
	must(t, os.WriteFile(filepath.Join(p.Home, "reports", "acme", "production"), []byte("x"), 0o644))
	_, h := newTest(t, Options{Paths: p})
	if r := do(h, "GET", "/api/run?org=acme&env=production&run=current", nil, nil); r.code != 500 {
		t.Fatal(r.code, r.body)
	}
}

func TestAPIPrompt(t *testing.T) {
	p, env := fixtureHome(t)
	type call struct {
		org, env, lang string
		ids            []string
		actions        int
	}
	var got []call
	_, h := newTest(t, Options{Paths: p, Prompt: func(o *config.Org, e string, v *report.View, ids []string, lang string) string {
		got = append(got, call{o.ID, e, lang, ids, len(v.Actions)})
		return "fix " + strings.Join(ids, " ")
	}})
	base := "/api/prompt?org=acme&env=production&run=2026-11-02_100000"
	r := do(h, "GET", base+"&ids=a1,,a2", nil, nil)
	if r.code != 200 || r.body != `{"text":"fix a1 a2"}` {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "GET", base+"&ids=a3&lang=ru", nil, nil); r.code != 200 {
		t.Fatal(r.code)
	}
	if len(got) != 2 || got[0].org != "acme" || got[0].env != "production" || got[0].lang != "en" ||
		got[1].lang != "ru" || got[0].actions == 0 || len(got[0].ids) != 2 {
		t.Fatalf("%+v", got)
	}
	// unknown run: 404
	if r := do(h, "GET", "/api/prompt?org=acme&env=production&run=nope", nil, nil); r.code != 404 {
		t.Fatal(r.code)
	}
	// a stored view of the current version that does not fit the View type: 500
	d := filepath.Join(env, "2026-11-01_120000")
	must(t, os.WriteFile(filepath.Join(d, "view.json"), []byte(`{"version": 11, "actions": "none"}`), 0o644))
	if r := do(h, "GET", "/api/prompt?org=acme&env=production&run=2026-11-01_120000", nil, nil); r.code != 500 {
		t.Fatal(r.code, r.body)
	}

	// without a prompt builder: 501, not logged as an error
	_, h2 := newTest(t, Options{Paths: p})
	if r := do(h2, "GET", base, nil, nil); r.code != 501 {
		t.Fatal(r.code, r.body)
	}
}

// globErrFS: a locales FS whose listing or reading fails.
type globErrFS struct{ glob bool }

func (f globErrFS) Open(string) (fs.File, error) { return nil, fs.ErrPermission }

func (f globErrFS) Glob(string) ([]string, error) {
	if f.glob {
		return nil, errors.New("glob failed")
	}
	return []string{"en.json"}, nil
}

func TestPageAssetErrors(t *testing.T) {
	page := &fstest.MapFile{Data: []byte("<html>/*I18N_UI*/{}</html>")}
	web := fstest.MapFS{"index.html": page, "classic.html": page, "logo.png": {Data: []byte("png")}}
	t.Cleanup(func() { webFS, localesFS = assets.Web, assets.Locales })
	for _, c := range []struct {
		name    string
		web     fs.FS
		locales fs.FS
		want    string
	}{
		{"no page", fstest.MapFS{"logo.png": web["logo.png"], "classic.html": page}, assets.Locales(), "index.html"},
		{"no classic page", fstest.MapFS{"logo.png": web["logo.png"], "index.html": page}, assets.Locales(), "classic.html"},
		{"no logo", fstest.MapFS{"index.html": page, "classic.html": page}, assets.Locales(), "logo.png"},
		{"glob", web, globErrFS{glob: true}, "glob failed"},
		{"read", web, globErrFS{}, "permission denied"},
		{"bad json", web, fstest.MapFS{"en.json": {Data: []byte("{")}}, "locales/en.json"},
	} {
		webFS = func() fs.FS { return c.web }
		localesFS = func() fs.FS { return c.locales }
		if _, err := New(Options{Paths: testHome(t)}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// a locale without UI strings is left out of the page
	webFS = func() fs.FS { return web }
	localesFS = func() fs.FS {
		return fstest.MapFS{"en.json": {Data: []byte(`{"ui": {"a": "</b>"}}`)}, "xx.json": {Data: []byte(`{"ui": {}}`)}}
	}
	s, err := New(Options{Paths: testHome(t)})
	must(t, err)
	if string(s.page) != `<html>{"en": {"a": "<\/b>"}}</html>` {
		t.Fatal(string(s.page))
	}
}

func TestServeLifecycle(t *testing.T) {
	updated := make(chan struct{})
	s, _ := newTest(t, Options{UpdateDB: func(ctx context.Context, out io.Writer) error {
		close(updated)
		<-ctx.Done()
		return ctx.Err()
	}})
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, "127.0.0.1", 0, pw); pw.Close() }()
	line := make([]byte, 256)
	n, _ := pr.Read(line)
	go func() { _, _ = io.Copy(io.Discard, pr) }()
	out := string(line[:n])
	if !strings.Contains(out, "kanareika dashboard on http://127.0.0.1:") || !strings.Contains(out, "read-only") {
		t.Fatal(out)
	}
	// a DB update in flight when the server stops is cancelled and waited for
	if !s.db.start() {
		t.Fatal("update not started")
	}
	select {
	case <-updated:
	case <-time.After(5 * time.Second):
		t.Fatal("update never ran")
	}
	cancel()
	must(t, <-done)
	s.db.mu.Lock()
	running, uerr := s.db.running, s.db.err
	s.db.mu.Unlock()
	if running || uerr != context.Canceled.Error() {
		t.Fatal(running, uerr)
	}

	// a listener that fails: the error comes back at once
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	ln.Close()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	s2, _ := newTest(t, Options{})
	if err := s2.serve(ctx2, ln, "127.0.0.1", io.Discard); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
