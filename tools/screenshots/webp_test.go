package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/tools/internal/webp"
)

// TestShotWebP: each picture Chrome takes is kept as lossless WebP, the PNG removed; a missing cwebp says so.
func TestShotWebP(t *testing.T) {
	oldC, oldE := capture, webp.Encode
	t.Cleanup(func() { capture, webp.Encode = oldC, oldE })
	capture = func(_, _, png string, _, _ int, _ ...string) error { return os.WriteFile(png, []byte("png"), 0o644) }
	webp.Encode = func(_, out string) error { return os.WriteFile(out, []byte("webp"), 0o644) }
	dir := t.TempDir()
	if err := shot("chrome", "file:///x", filepath.Join(dir, "tui-en.png"), 10, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tui-en.webp")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tui-en.png")); err == nil {
		t.Fatal("the PNG stays")
	}
	webp.Encode = func(string, string) error {
		return errors.New("cwebp not found: brew install webp, or apt install webp")
	}
	if err := shot("chrome", "file:///x", filepath.Join(dir, "web-en.png"), 10, 10); err == nil || !strings.Contains(err.Error(), "cwebp") {
		t.Fatal(err)
	}
	capture = func(string, string, string, int, int, ...string) error { return errors.New("no chrome") }
	if err := shot("chrome", "file:///x", filepath.Join(dir, "web-en.png"), 10, 10); err == nil {
		t.Fatal("chrome's failure")
	}
}
