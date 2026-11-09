package webp

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFromPNG(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.png")
	if err := os.WriteFile(p, []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := Encode
	t.Cleanup(func() { Encode = old })
	Encode = func(png, out string) error { return os.WriteFile(out, []byte("webp"), 0o644) }
	out, err := FromPNG(p)
	if err != nil || out != filepath.Join(dir, "a.webp") {
		t.Fatal(out, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("the PNG stays")
	}
}

// TestEncode: a real 1x1 PNG through cwebp, when it is installed.
func TestEncode(t *testing.T) {
	if _, err := exec.LookPath("cwebp"); err != nil {
		t.Skip("no cwebp")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "a.png")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{255, 210, 63, 255})
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := Encode(p, filepath.Join(dir, "a.webp")); err != nil {
		t.Fatal(err)
	}
	if err := Encode(filepath.Join(dir, "missing.png"), filepath.Join(dir, "b.webp")); err == nil {
		t.Error("a missing file must fail")
	}
}
