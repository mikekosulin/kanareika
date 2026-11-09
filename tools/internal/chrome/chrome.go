// Package chrome renders pages to PNG with headless Chrome, for the repository's pictures (tools/brand) and
// screenshots (tools/screenshots).
package chrome

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// seams for tests: Chrome itself, where it is looked for, and the working directory
var (
	run = func(ctx context.Context, bin string, args ...string) error {
		out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", bin, err, bytes.TrimSpace(out))
		}
		return nil
	}
	lookPath = exec.LookPath
	goos     = runtime.GOOS
	absPath  = filepath.Abs
	macApps  = []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium"}
)

// Find: Chrome or Chromium on this machine, "" if there is none.
func Find() string {
	if goos == "darwin" {
		for _, p := range macApps {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := lookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// Shot: the page at url as a PNG at 2x, w×h CSS pixels, transparent where the page is (a banner's rounded
// corners); extra flags go to Chrome before the url (a time budget for pages that load data, a dark theme).
func Shot(bin, url, png string, w, h int, extra ...string) error {
	shot, err := absPath(png)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := append([]string{"--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
		"--default-background-color=00000000", fmt.Sprintf("--window-size=%d,%d", w, h), "--screenshot=" + shot},
		extra...)
	_ = os.Remove(shot) // a picture from before must not pass for this one
	runErr := run(ctx, bin, append(args, url)...)
	if wholePNG(shot) {
		return nil // Chrome sometimes fails on its way out ("Teardown watchdog expired") after the picture is written
	}
	if runErr != nil {
		return runErr
	}
	return errors.New("chrome wrote no picture: " + shot)
}

// wholePNG: path is a complete PNG: the signature and the closing IEND chunk.
func wholePNG(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && len(b) > 20 && bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) &&
		bytes.Equal(b[len(b)-8:len(b)-4], []byte("IEND"))
}

// FileURL: a local file as Chrome opens it: file:///home/x/og.html, file:///C:/x/og.html on Windows.
func FileURL(path string) (string, error) {
	abs, err := absPath(path)
	if err != nil {
		return "", err
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "file://" + p, nil
}
