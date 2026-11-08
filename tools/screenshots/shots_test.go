package main

import (
	"errors"
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

// TestShots: a TUI and a web picture per language, at their sizes; the web page in the language, over the org
// and environment, dark; the demo's trivy cache and feeds, times in UTC.
func TestShots(t *testing.T) {
	calls := fakeShots(t)
	home, out := t.TempDir(), filepath.Join(t.TempDir(), "shots")
	if err := shots(out, home, "", "acme", "production", "150x26", "2", "2026-11-07T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2*len(i18n.Langs()) {
		t.Fatalf("%d pictures", len(*calls))
	}
	tui, web := (*calls)[0], (*calls)[1]
	if !strings.HasPrefix(tui, "chrome file:///") || !strings.Contains(tui, "tui-en.png 1207x472") {
		t.Error(tui)
	}
	for _, want := range []string{"/?lang=en#env=production&org=acme", "web-en.png 1600x1000", "--force-dark-mode", "--virtual-time-budget="} {
		if !strings.Contains(web, want) {
			t.Errorf("%q not in %s", want, web)
		}
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "/?lang=ja#") {
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
