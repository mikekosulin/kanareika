package main

import (
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/i18n"
)

// fakeChrome: writes the picture Chrome was asked for and remembers what it was asked.
func fakeChrome(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	old := shot
	t.Cleanup(func() { shot = old })
	shot = func(bin, url, png string, w, h int, _ ...string) error {
		calls = append(calls, []string{bin, url, png, fmt.Sprintf("%dx%d", w, h)})
		return os.WriteFile(png, []byte("png"), 0o644)
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

// TestRun: the social preview and a banner per language, dark and light, each a page and a picture rendered from it.
func TestRun(t *testing.T) {
	calls := fakeChrome(t)
	out := filepath.Join(t.TempDir(), "brand")
	if err := run(out, logo(t), ".", "chrome"); err != nil {
		t.Fatal(err)
	}
	names := []string{"og"}
	for _, l := range langs {
		names = append(names, "banner-"+l.Code, "banner-"+l.Code+"-light")
	}
	for _, n := range names {
		for _, ext := range []string{".html", ".png"} {
			if _, err := os.Stat(filepath.Join(out, n+ext)); err != nil {
				t.Error(err)
			}
		}
	}
	if len(*calls) != len(names) {
		t.Fatalf("%d renders", len(*calls))
	}
	if c := (*calls)[0]; c[0] != "chrome" || !strings.HasPrefix(c[1], "file:///") || c[3] != "1280x640" {
		t.Error(c)
	}
	if c := (*calls)[1]; c[3] != "1280x360" {
		t.Error(c)
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
		"og":        {"What to patch first.", "Access", "■ 2 P1", "■ 3 P3", "■ 2 P4", "openssl 3.0.13 → 3.0.15", "kernel 5.14.0-427"},
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
	// the light banner: the same words on a light page; the dark ones and the preview stay dark
	for _, l := range langs {
		dark, light := page["banner-"+l.Code], page["banner-"+l.Code+"-light"]
		if !strings.Contains(light, `<body class="light">`) || !strings.Contains(light, template.HTMLEscapeString(l.Accent)) {
			t.Errorf("banner-%s-light: not light or not %s", l.Code, l.Code)
		}
		if strings.Contains(dark, `<body class="light">`) {
			t.Errorf("banner-%s: light", l.Code)
		}
	}
	if strings.Contains(page["og"], `class="light"`) {
		t.Error("og: light")
	}
	if strings.Contains(page["banner-en"], "CVE-0000-90210") {
		t.Error("banner shows more than its rows")
	}
	// the social preview is read at ~450px wide: few tabs, few rows, no CVE column
	for _, w := range []string{"Network", "NTP drift", "CVE-0000-90017"} {
		if strings.Contains(page["og"], w) {
			t.Errorf("og shows more than it can at preview size: %q", w)
		}
	}
}

// TestDemoData: what the pictures show is invented: CVE ids of the year 0000, which the CVE program never
// assigns (made-up ids of the current year turn real as its numbers come up), and the demo's hosts.
func TestDemoData(t *testing.T) {
	cve := regexp.MustCompile(`^CVE-0000-\d{4,}$`)
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
	old := findChrome
	t.Cleanup(func() { findChrome = old })
	findChrome = func() string { return "" }
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

	shot = func(string, string, string, int, int, ...string) error { return errors.New("crashed") }
	if err := run(t.TempDir(), l, ".", "chrome"); err == nil || !strings.Contains(err.Error(), "crashed") {
		t.Error(err)
	}
	old := fileURL
	t.Cleanup(func() { fileURL = old })
	fileURL = func(string) (string, error) { return "", errors.New("no cwd") }
	if err := render("chrome", "og.html", "og.png", 1, 1); err == nil {
		t.Error("no cwd")
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
	if died != nil || len(*calls) != 1+2*len(langs) {
		t.Fatal(died, len(*calls))
	}

	flag.CommandLine = flag.NewFlagSet("brand", flag.ContinueOnError)
	os.Args = []string{"brand", "-out", out, "-logo", filepath.Join(out, "none.png")}
	main()
	if died == nil {
		t.Fatal("no logo, not fatal")
	}
}

// TestEveryLanguage: a banner for every language the interfaces speak, and none for one they do not.
func TestEveryLanguage(t *testing.T) {
	var codes []string
	for _, l := range langs {
		codes = append(codes, l.Code)
	}
	want := i18n.Langs()
	slices.Sort(codes)
	slices.Sort(want)
	if !slices.Equal(codes, want) {
		t.Fatalf("banners %v, languages %v", codes, want)
	}
}
