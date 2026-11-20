package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/server"
)

// fakeShots: Chrome found, writing every picture it is asked for; what it was asked, in order.
func fakeShots(t *testing.T) *[]string {
	t.Helper()
	for _, k := range []string{"TRIVY_CACHE_DIR", "KANAREIKA_FEEDS_DIR", "TZ"} {
		t.Setenv(k, os.Getenv(k)) // restored after the test: shots sets them
	}
	var calls []string
	oldShot, oldFind := shot, findChrome
	t.Cleanup(func() { shot, findChrome = oldShot, oldFind })
	findChrome = func() string { return "chrome" }
	shot = func(bin, url, png string, w, h int, extra ...string) error {
		calls = append(calls, strings.Join(append([]string{bin, url, filepath.Base(png), strconv.Itoa(w) + "x" + strconv.Itoa(h)}, extra...), " "))
		return os.WriteFile(png, []byte("png"), 0o644)
	}
	return &calls
}

// TestShots: per language a TUI picture and the web page's ToDo grouped by CVE, dark and light, at their sizes, in
// the language, over the org and environment; the demo's trivy cache and feeds, times in UTC.
func TestShots(t *testing.T) {
	calls := fakeShots(t)
	home, out := t.TempDir(), filepath.Join(t.TempDir(), "shots")
	if err := shots(out, home, "", "acme", "production", "150x26", "2", "2026-11-07T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 4*len(i18n.Langs()) {
		t.Fatalf("%d pictures", len(*calls))
	}
	tui, tuiLight, web := (*calls)[0], (*calls)[1], (*calls)[2]
	if !strings.HasPrefix(tui, "chrome file:///") || !strings.Contains(tui, "tui-en.png 1207x472") {
		t.Error(tui)
	}
	if !strings.Contains(tuiLight, "tui-en-light.png 1207x472") {
		t.Error(tuiLight)
	}
	dark, _ := os.ReadFile(filepath.Join(out, "tui-en.html"))
	light, _ := os.ReadFile(filepath.Join(out, "tui-en-light.html"))
	if !strings.Contains(string(dark), "background:#141413") || !strings.Contains(string(light), "background:#fafaf8") ||
		!strings.Contains(string(light), "color:#1f1f1d") || !strings.Contains(string(light), "#ff5f57") || string(dark) == string(light) {
		t.Error("the light terminal window")
	}
	for _, want := range []string{"/todo?by=cve&env=production&lang=en&org=acme", "web-en.png 1600x1000", "--force-dark-mode", "--virtual-time-budget="} {
		if !strings.Contains(web, want) {
			t.Errorf("%q not in %s", want, web)
		}
	}
	if light := (*calls)[3]; !strings.Contains(light, "web-en-light.png 1600x1000") || strings.Contains(light, "--force-dark-mode") {
		t.Error(light)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "lang=ja&") {
		t.Error("no Japanese page")
	}
	if os.Getenv("TRIVY_CACHE_DIR") != filepath.Join(home, "trivy") || os.Getenv("TZ") != "UTC" {
		t.Error(os.Getenv("TRIVY_CACHE_DIR"), os.Getenv("TZ"))
	}
	b, err := os.ReadFile(filepath.Join(out, "tui-ja.html"))
	if err != nil || !strings.Contains(string(b), `<b class="w">`) || !strings.HasPrefix(string(b), "<!doctype html>") {
		t.Errorf("tui-ja.html: %v", err)
	}
	if tuiW, tuiH := tuiSize(80, 20); tuiW != 658 || tuiH != 377 {
		t.Error(tuiW, tuiH)
	}
}

// TestShotsErrors: each failure stops with its reason.
func TestShotsErrors(t *testing.T) {
	fakeShots(t)
	home := t.TempDir()
	try := func(name string, size, at string, out string) {
		t.Helper()
		if out == "" {
			out = t.TempDir()
		}
		if err := shots(out, home, "chrome", "acme", "production", size, "", at); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	findChrome = func() string { return "" }
	if err := shots(t.TempDir(), home, "", "", "", "80x20", "", ""); err == nil || !strings.Contains(err.Error(), "-chrome") {
		t.Error(err)
	}
	try("size", "big", "", "")
	try("time", "80x20", "yesterday", "")
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	try("out under a file", "80x20", "", filepath.Join(file, "out"))
	blocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(blocked, "tui-en.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	try("page not written", "80x20", "", blocked)

	oldEnv, oldServer, oldURL, oldShot := setenv, newServer, fileURL, shot
	t.Cleanup(func() { setenv, newServer, fileURL, shot = oldEnv, oldServer, oldURL, oldShot })
	setenv = func(string, string) error { return errors.New("env") }
	try("environment", "80x20", "", "")
	setenv = oldEnv
	newServer = func(server.Options) (*server.Server, error) { return nil, errors.New("no assets") }
	try("server", "80x20", "", "")
	newServer = oldServer
	fileURL = func(string) (string, error) { return "", errors.New("no cwd") }
	try("file url", "80x20", "", "")
	fileURL = oldURL
	for _, failing := range []string{"tui-", "web-"} {
		shot = func(_, _, png string, _, _ int, _ ...string) error {
			if strings.HasPrefix(filepath.Base(png), failing) {
				return errors.New("crashed")
			}
			return os.WriteFile(png, nil, 0o644)
		}
		try(failing+" shot", "80x20", "", "")
	}
}

// fixtureHome: a copy of the fixture home of package remediate (an org with a current state to show).
func fixtureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.CopyFS(home, os.DirFS("../../internal/remediate/testdata/fixture/home")); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestShotsOpenFirstNode: with data to show, the web shots open the most urgent row's details beside the list.
func TestShotsOpenFirstNode(t *testing.T) {
	calls := fakeShots(t)
	home := fixtureHome(t)
	if err := shots(t.TempDir(), home, "", "acme", "production", "80x20", "", "2026-11-07T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	web := (*calls)[2]
	if !strings.Contains(web, "web-en.png") || !strings.Contains(web, "node=") || !strings.Contains(web, "wide=0") {
		t.Fatal(web)
	}
	if light := (*calls)[3]; !strings.Contains(light, "web-en-light.png") || !strings.Contains(light, "node=") {
		t.Fatal(light)
	}
}

// TestShotsWebFails: the web page's first row that cannot be read, or its light picture that cannot be taken, stops
// the shots with the reason.
func TestShotsWebFails(t *testing.T) {
	fakeShots(t)
	home := fixtureHome(t)
	if err := os.WriteFile(filepath.Join(home, "reports", "acme", "production", "current", "findings.json.gz"), []byte("not gzip"),
		0o644); err != nil {
		t.Fatal(err)
	}
	err := shots(t.TempDir(), home, "chrome", "acme", "production", "80x20", "", "2026-11-07T12:00:00Z")
	if err == nil || !strings.Contains(err.Error(), "/api/tree") {
		t.Errorf("a broken current state: %v", err)
	}

	old := shot
	shot = func(bin, url, png string, w, h int, extra ...string) error {
		if strings.HasSuffix(png, "web-en-light.png") {
			return errors.New("crashed")
		}
		return old(bin, url, png, w, h, extra...)
	}
	if err := shots(t.TempDir(), t.TempDir(), "chrome", "acme", "production", "80x20", "", ""); err == nil || err.Error() != "crashed" {
		t.Errorf("the light web picture: %v", err)
	}
}

// TestFirstNode: the first row of ToDo by CVE, asked as one row of the current state's top level; none when there
// is no such org or run, or no row; an error for any other answer.
func TestFirstNode(t *testing.T) {
	var asked url.Values
	answer := func(code int, body string) string {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/tree" {
				asked = r.URL.Query()
			}
			w.WriteHeader(code)
			io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	id, err := firstNode(answer(200, `{"nodes":[{"id":"c:CVE-0000-0001"},{"id":"c:CVE-0000-0002"}]}`), "acme", "production")
	if err != nil || id != "c:CVE-0000-0001" {
		t.Fatalf("%q %v", id, err)
	}
	want := url.Values{"org": {"acme"}, "env": {"production"}, "run": {"current"}, "by": {"cve"}, "levels": {"0"}, "limit": {"1"}}
	if asked.Encode() != want.Encode() {
		t.Errorf("asked %v", asked)
	}
	for _, c := range []struct {
		code      int
		body, err string
	}{
		{404, `{"error":"no such run"}`, ""},
		{200, `{"nodes":[]}`, ""},
		{500, `{"error":"broken"}`, "/api/tree: 500 Internal Server Error"},
		{200, `{"nodes":`, "/api/tree: unexpected EOF"},
	} {
		id, err := firstNode(answer(c.code, c.body), "acme", "production")
		if id != "" || (err == nil) != (c.err == "") || err != nil && err.Error() != c.err {
			t.Errorf("%d %s: %q %v", c.code, c.body, id, err)
		}
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	if _, err := firstNode(gone.URL, "acme", "production"); err == nil {
		t.Error("a server that is gone")
	}
}

// TestANSIHTML: 24-bit colors, bold and italic as spans, each reset on its own code; HTML escaped; a wide
// character in a box two columns wide.
func TestANSIHTML(t *testing.T) {
	for in, want := range map[string]string{
		"plain <&>": "plain &lt;&amp;&gt;",
		"\x1b[38;2;255;0;16;48;2;1;2;3;1;3ma\x1b[22;23;39;49mb\x1b[mc": `<span style="color:#ff0010;background:#010203;font-weight:700;font-style:italic">a</span>bc`,
		"\x1b[1mx\x1b[0my": `<span style="font-weight:700">x</span>y`,
		"\x1b[38;5;1mz":    "z", // 256 colors: not used by the TUI, ignored
		"中a":               `<b class="w">中</b>a`,
		"\x1b[38;2;1;2;3m": "",
	} {
		if got := ansiHTML(in); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}
