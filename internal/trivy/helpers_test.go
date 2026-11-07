package trivy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTail(t *testing.T) {
	if tail("abc", 5) != "abc" || tail("абвгд", 2) != "гд" {
		t.Fatal(tail("абвгд", 2))
	}
}

func TestCacheDir(t *testing.T) {
	t.Setenv("TRIVY_CACHE_DIR", "/x/trivy-cache")
	if CacheDir() != "/x/trivy-cache" {
		t.Fatal(CacheDir())
	}
	t.Setenv("TRIVY_CACHE_DIR", "")
	if d := CacheDir(); !strings.HasSuffix(d, filepath.Join("", "trivy")) {
		t.Fatal(d)
	}
}
