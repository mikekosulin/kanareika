package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanLimits(t *testing.T) {
	p := PathsAt(t.TempDir())
	if l := ScanLimits(p, nil); l != (Limits{Limit{DefaultParallel, "default"}, Limit{DefaultTrivyParallel, "default"}}) {
		t.Fatalf("defaults %+v", l)
	}
	ten, three := 10, 3
	if err := SetScanLimits(p, &ten, &three); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(p.Policy, "settings.yml"))
	if !strings.Contains(string(b), "keep_full: 12") || !strings.Contains(string(b), "# Run retention") {
		t.Fatalf("the rest of the file and its comments must stay:\n%s", b)
	}
	o := &Org{Data: map[string]any{"access": map[string]any{"user": "u", "parallel": float64(4)}}}
	l := ScanLimits(p, o)
	if l.Parallel != (Limit{4, "org"}) || l.TrivyParallel != (Limit{3, "settings"}) {
		t.Fatalf("org over settings %+v", l)
	}
	if got := l.Parallel.Override(100); got != (Limit{MaxParallel, "flag"}) {
		t.Fatalf("flag %+v", got)
	}
	if got := l.Parallel.Override(0); got != l.Parallel {
		t.Fatalf("no flag %+v", got)
	}
	zero := 0
	if err := SetScanLimits(p, &zero, nil); err != nil {
		t.Fatal(err)
	}
	if l := ScanLimits(p, nil); l.Parallel.Source != "default" || l.TrivyParallel.Value != 3 {
		t.Fatalf("0 = back to the default %+v", l)
	}
	bad := 65
	if SetScanLimits(p, &bad, nil) == nil {
		t.Fatal("65 accepted")
	}
	// the built-in settings.yml states the built-in defaults
	b, err := Policy(PathsAt(t.TempDir()), "settings.yml")
	if err != nil || !strings.Contains(string(b), "parallel: 8") || !strings.Contains(string(b), "trivy_parallel: 2") {
		t.Fatalf("built-in settings.yml: %v\n%s", err, b)
	}
}
