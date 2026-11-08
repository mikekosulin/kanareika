package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeChrome: writes the picture Chrome was asked for and remembers the arguments.
func fakeChrome(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	old := runChrome
	t.Cleanup(func() { runChrome = old })
	runChrome = func(_ context.Context, bin string, args ...string) error {
		calls = append(calls, append([]string{bin}, args...))
		for _, a := range args {
			if p, ok := strings.CutPrefix(a, "--screenshot="); ok {
				return os.WriteFile(p, []byte("png"), 0o644)
			}
		}
		return nil
	}
	return &calls
}

func logo(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "logo.png")
	if err := os.WriteFile(p, []byte("\x89PNG"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRun: the social preview and a banner per language, each a page and a picture rendered at 2x from it.
func TestRun(t *testing.T) {
	calls := fakeChrome(t)
	out := filepath.Join(t.TempDir(), "brand")
	if err := run(out, logo(t), ".", "chrome"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"og", "banner-en", "banner-ru", "banner-zh"} {
		for _, ext := range []string{".html", ".png"} {
			if _, err := os.Stat(filepath.Join(out, n+ext)); err != nil {
				t.Error(err)
			}
		}
	}
	if len(*calls) != 4 {
		t.Fatalf("%d renders", len(*calls))
	}
	args := strings.Join((*calls)[0], " ")
	for _, want := range []string{"chrome --headless=new", "--force-device-scale-factor=2", "--window-size=1280,640", "file:///"} {
		if !strings.Contains(args, want) {
			t.Errorf("%q not in %s", want, args)
		}
	}
	if !strings.Contains(strings.Join((*calls)[1], " "), "--window-size=1280,360") {
		t.Error((*calls)[1])
	}
}

// TestPictures: each picture in its language, with the canary inline and the TUI's tab names; the banner shows
// the first rows only; the counts in the preview are the rows'.
func TestPictures(t *testing.T) {
	pics, err := pictures("data:image/png;base64,AAAA", pages(t))
	if err != nil {
		t.Fatal(err)
	}
	page := map[string]string{}
	for _, p := range pics {
		page[p.name] = string(p.html)
		if !strings.Contains(page[p.name], `src="data:image/png;base64,AAAA"`) {
			t.Errorf("%s: no logo", p.name)
		}
		if strings.Contains(page[p.name], "ZgotmplZ") {
			t.Errorf("%s: a value the template refused", p.name)
		}
	}
	for name, want := range map[string][]string{
		"og":        {"What to patch first.", "Network", "■ 2 P1", "■ 3 P3", "■ 2 P4", "CVE-2026-90210", "stage-web-01"},
		"banner-en": {`lang="en"`, "What to patch first.", "ToDo"},
		"banner-ru": {`lang="ru"`, "Начните с главного.", "Что делать", "Здоровье"},
		"banner-zh": {`lang="zh"`, "从最重要的开始", "待办", "健康"},
	} {
		for _, w := range want {
			if !strings.Contains(page[name], w) {
				t.Errorf("%s: no %q", name, w)
			}
		}
	}
	if strings.Contains(page["banner-en"], "CVE-2026-90210") {
		t.Error("banner shows more than its rows")
	}
}

// TestDemoData: what the pictures show is invented: CVE ids of the demo's made-up range, the demo's hosts.
func TestDemoData(t *testing.T) {
	cve := regexp.MustCompile(`^CVE-2026-9\d{4}$`)
	hosts := map[string]bool{"web-01": true, "web-02": true, "db-01": true, "stage-web-01": true}
	for _, l := range langs {
		for _, r := range l.Rows {
			if strings.HasPrefix(r.Kind, "CVE-") && !cve.MatchString(r.Kind) {
				t.Errorf("%s: %s is not a made-up id", l.Code, r.Kind)
			}
			if !hosts[r.Host] {
				t.Errorf("%s: %s is not a demo host", l.Code, r.Host)
			}
		}
	}
}

// TestNoChrome: pages only, and a word on why.
func TestNoChrome(t *testing.T) {
	calls := fakeChrome(t)
	oldLook, oldOS := lookPath, goos
	t.Cleanup(func() { lookPath, goos = oldLook, oldOS })
	lookPath = func(string) (string, error) { return "", errors.New("none") }
	goos = "linux"
	out := t.TempDir()
	if err := run(out, logo(t), ".", ""); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatal(*calls)
	}
	if _, err := os.Stat(filepath.Join(out, "og.png")); err == nil {
		t.Error("a picture without Chrome")
	}
	if _, err := os.Stat(filepath.Join(out, "og.html")); err != nil {
		t.Error(err)
	}
}

// TestFindChrome: the macOS app first, then the PATH.
func TestFindChrome(t *testing.T) {
	oldLook, oldOS, oldApps := lookPath, goos, macApps
	t.Cleanup(func() { lookPath, goos, macApps = oldLook, oldOS, oldApps })
	app := filepath.Join(t.TempDir(), "Google Chrome")
	if err := os.WriteFile(app, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	goos, macApps = "darwin", []string{filepath.Join(t.TempDir(), "missing"), app}
	if got := findChrome(); got != app {
		t.Fatal(got)
	}
	goos = "linux"
	lookPath = func(n string) (string, error) {
		if n == "chromium" {
			return "/usr/bin/chromium", nil
		}
		return "", errors.New("none")
	}
	if got := findChrome(); got != "/usr/bin/chromium" {
		t.Fatal(got)
	}
}

// TestFileURL: three slashes on every system.
func TestFileURL(t *testing.T) {
	if got := fileURL("/home/x/og.html"); got != "file:///home/x/og.html" {
		t.Error(got)
	}
	if got := fileURL(`C:\x\og.html`); got != "file:///C:/x/og.html" && got != `file:///C:\x\og.html` {
		t.Error(got)
	}
}

// TestErrors: each failure stops the run with its reason.
func TestErrors(t *testing.T) {
	fakeChrome(t)
	l := logo(t)
	if err := run(t.TempDir(), filepath.Join(t.TempDir(), "none.png"), ".", "chrome"); err == nil {
		t.Error("no logo")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(filepath.Join(file, "out"), l, ".", "chrome"); err == nil {
		t.Error("out under a file")
	}
	blocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(blocked, "og.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := run(blocked, l, ".", "chrome"); err == nil {
		t.Error("page not written")
	}

	runChrome = func(context.Context, string, ...string) error { return errors.New("crashed") }
	if err := run(t.TempDir(), l, ".", "chrome"); err == nil || !strings.Contains(err.Error(), "crashed") {
		t.Error(err)
	}
	runChrome = func(context.Context, string, ...string) error { return nil }
	if err := run(t.TempDir(), l, ".", "chrome"); err == nil || !strings.Contains(err.Error(), "no picture") {
		t.Error(err)
	}

	oldAbs := absPath
	t.Cleanup(func() { absPath = oldAbs })
	for _, bad := range []string{".html", ".png"} {
		absPath = func(p string) (string, error) {
			if strings.HasSuffix(p, bad) {
				return "", errors.New("no cwd")
			}
			return p, nil
		}
		if err := render("chrome", "og.html", "og.png", 1, 1); err == nil {
			t.Error(bad)
		}
	}
}

// pages: the real pages, as run reads them.
func pages(t *testing.T) sources {
	t.Helper()
	s, err := load(".")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestBadTemplates: a page that is missing, does not parse or does not fit its data.
func TestBadTemplates(t *testing.T) {
	fakeChrome(t)
	real := pages(t)
	for _, c := range []struct{ og, banner string }{
		{"{{", real.banner}, {real.og, "{{"}, {"{{.L.Nope}}", real.banner}, {real.og, "{{.L.Nope}}"},
	} {
		if _, err := pictures("x", sources{c.og, c.banner, real.css}); err == nil {
			t.Errorf("%q %q", c.og[:min(len(c.og), 12)], c.banner[:min(len(c.banner), 12)])
		}
		dir := t.TempDir()
		for name, body := range map[string]string{"og.html": c.og, "banner.html": c.banner, "style.css": real.css} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := run(t.TempDir(), logo(t), dir, "chrome"); err == nil {
			t.Error("run with a bad page")
		}
	}
	if err := run(t.TempDir(), logo(t), t.TempDir(), "chrome"); err == nil {
		t.Error("no pages")
	}
}

// TestMain_: the flags reach run; a failure is fatal.
func TestMain_(t *testing.T) {
	calls := fakeChrome(t)
	oldArgs, oldFatal, oldFlags := os.Args, fatal, flag.CommandLine
	t.Cleanup(func() { os.Args, fatal, flag.CommandLine = oldArgs, oldFatal, oldFlags })
	var died []any
	fatal = func(v ...any) { died = v }

	flag.CommandLine = flag.NewFlagSet("brand", flag.ContinueOnError)
	out := t.TempDir()
	os.Args = []string{"brand", "-out", out, "-logo", logo(t), "-pages", ".", "-chrome", "chrome"}
	main()
	if died != nil || len(*calls) != 4 {
		t.Fatal(died, len(*calls))
	}

	flag.CommandLine = flag.NewFlagSet("brand", flag.ContinueOnError)
	os.Args = []string{"brand", "-out", out, "-logo", filepath.Join(out, "none.png")}
	main()
	if died == nil {
		t.Fatal("no logo, not fatal")
	}
}

// TestRunChrome: the real launcher, on a program that exits 0 (the test binary itself) and one that fails.
func TestRunChrome(t *testing.T) {
	if err := runChrome(context.Background(), os.Args[0], "-test.run=^$"); err != nil {
		t.Fatal(err)
	}
	err := runChrome(context.Background(), os.Args[0], "-test.nosuchflag")
	if err == nil || !strings.Contains(err.Error(), "nosuchflag") {
		t.Fatal(err)
	}
}
