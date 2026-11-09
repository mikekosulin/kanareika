// Package webp turns the PNGs that headless Chrome writes into lossless WebP for the README (pixel for pixel the
// same, about a third of the size). The social preview stays PNG: link previews do not all read WebP.
package webp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Encode writes png as lossless WebP to out with cwebp (libwebp); a variable so tests need no cwebp.
var Encode = func(png, out string) error {
	bin, err := exec.LookPath("cwebp")
	if err != nil {
		return errors.New("cwebp not found: brew install webp, or apt install webp")
	}
	if b, err := exec.Command(bin, "-quiet", "-lossless", "-z", "9", png, "-o", out).CombinedOutput(); err != nil {
		return fmt.Errorf("cwebp %s: %w %s", png, err, strings.TrimSpace(string(b)))
	}
	return nil
}

// FromPNG converts path (a .png) to the .webp next to it and removes the PNG; it returns the WebP's path.
func FromPNG(path string) (string, error) {
	out := strings.TrimSuffix(path, ".png") + ".webp"
	if err := Encode(path, out); err != nil {
		return "", err
	}
	return out, os.Remove(path)
}
