package chrome

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fake: Chrome that writes the picture it was asked for (or not) and remembers its arguments.
func fake(t *testing.T, write bool, fail error) *[]string {
	t.Helper()
	var args []string
	old := run
	t.Cleanup(func() { run = old })
	run = func(_ context.Context, bin string, a ...string) error {
		args = append([]string{bin}, a...)
		for _, x := range a {
			if p, ok := strings.CutPrefix(x, "--screenshot="); ok && write {
				return os.WriteFile(p, []byte("png"), 0o644)
			}
		}
		return fail
	}
	return &args
}

// TestShot: headless, 2x, the size given, the extra flags before the url; the picture must exist.
func TestShot(t *testing.T) {
	args := fake(t, true, nil)
	png := filepath.Join(t.TempDir(), "x.png")
	if err := Shot("chrome", "http://127.0.0.1:1/", png, 1600, 1000, "--force-dark-mode"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(*args, " ")
	for _, want := range []string{"chrome --headless=new", "--force-device-scale-factor=2", "--window-size=1600,1000",
		"--force-dark-mode http://127.0.0.1:1/"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q not in %s", want, got)
		}
	}

	fake(t, false, nil)
	if err := Shot("chrome", "u", png+"2", 1, 1); err == nil || !strings.Contains(err.Error(), "no picture") {
		t.Error(err)
	}
	fake(t, false, errors.New("crashed"))
	if err := Shot("chrome", "u", png, 1, 1); err == nil || !strings.Contains(err.Error(), "crashed") {
		t.Error(err)
	}
	old := absPath
	t.Cleanup(func() { absPath = old })
	absPath = func(string) (string, error) { return "", errors.New("no cwd") }
	if err := Shot("chrome", "u", png, 1, 1); err == nil {
		t.Error("no cwd")
	}
	if _, err := FileURL("x"); err == nil {
		t.Error("no cwd")
	}
}

// TestFind: the macOS app first, then the PATH; none: "".
func TestFind(t *testing.T) {
	oldLook, oldOS, oldApps := lookPath, goos, macApps
	t.Cleanup(func() { lookPath, goos, macApps = oldLook, oldOS, oldApps })
	app := filepath.Join(t.TempDir(), "Google Chrome")
	if err := os.WriteFile(app, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	goos, macApps = "darwin", []string{filepath.Join(t.TempDir(), "missing"), app}
	if got := Find(); got != app {
		t.Fatal(got)
	}
	goos = "linux"
	lookPath = func(n string) (string, error) {
		if n == "chromium" {
			return "/usr/bin/chromium", nil
		}
		return "", errors.New("none")
	}
	if got := Find(); got != "/usr/bin/chromium" {
		t.Fatal(got)
	}
	lookPath = func(string) (string, error) { return "", errors.New("none") }
	if got := Find(); got != "" {
		t.Fatal(got)
	}
}

// TestFileURL: three slashes on every system.
func TestFileURL(t *testing.T) {
	old := absPath
	t.Cleanup(func() { absPath = old })
	for in, want := range map[string]string{"/home/x/og.html": "file:///home/x/og.html", `C:\x\og.html`: "file:///C:/x/og.html"} {
		absPath = func(p string) (string, error) { return filepath.FromSlash(strings.ReplaceAll(p, `\`, "/")), nil }
		if got, _ := FileURL(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

// TestRun: the real launcher, on a program that exits 0 (the test binary itself) and one that fails.
func TestRun(t *testing.T) {
	if err := run(context.Background(), os.Args[0], "-test.run=^$"); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), os.Args[0], "-test.nosuchflag"); err == nil || !strings.Contains(err.Error(), "nosuchflag") {
		t.Fatal(err)
	}
}
