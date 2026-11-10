package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
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

func TestSetScanLimitsFiles(t *testing.T) {
	five := 5
	write := func(t *testing.T, body string) Paths {
		p := PathsAt(t.TempDir())
		if err := os.MkdirAll(p.Policy, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p.Policy, "settings.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// an existing scan: section is updated in place, its other keys and comments kept
	p := write(t, "retention:\n  keep_full: 3\nscan:\n  # mine\n  parallel: 2\n  other: x\n")
	if err := SetScanLimits(p, &five, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(p.Policy, "settings.yml"))
	if s := string(b); !strings.Contains(s, "parallel: 5") || strings.Contains(s, "parallel: 2") ||
		!strings.Contains(s, "# mine") || !strings.Contains(s, "other: x") || !strings.Contains(s, "keep_full: 3") {
		t.Fatalf("updated in place:\n%s", s)
	}
	if l := ScanLimits(p, nil); l.Parallel != (Limit{5, "settings"}) || l.TrivyParallel.Source != "default" {
		t.Fatalf("limits %+v", l)
	}
	// an empty file becomes a mapping with the scan section
	p = write(t, "")
	if err := SetScanLimits(p, nil, &five); err != nil {
		t.Fatal(err)
	}
	if l := ScanLimits(p, nil); l.TrivyParallel != (Limit{5, "settings"}) {
		t.Fatalf("from empty %+v", l)
	}
	// values that are not limits are ignored when read
	p = write(t, "scan:\n  parallel: 0\n  trivy_parallel: 2.5\n")
	if l := ScanLimits(p, nil); l.Parallel.Source != "default" || l.TrivyParallel.Source != "default" {
		t.Fatalf("bad values read as limits %+v", l)
	}
	p = write(t, "scan: [\n")
	if l := ScanLimits(p, nil); l.Parallel.Source != "default" {
		t.Fatalf("broken file read as limits %+v", l)
	}
	for name, body := range map[string]string{"broken": "scan: [\n", "a list": "- a\n", "scan a scalar": "scan: 5\n"} {
		if err := SetScanLimits(write(t, body), &five, nil); err == nil {
			t.Errorf("%s: written", name)
		}
	}
	// the policy dir cannot be made, or the file cannot be written
	p = PathsAt(t.TempDir())
	if err := os.WriteFile(p.Policy, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetScanLimits(p, &five, nil); err == nil {
		t.Error("policy dir is a file: written")
	}
	p = write(t, "retention: {}\n")
	if err := os.Mkdir(filepath.Join(p.Policy, "settings.yml.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SetScanLimits(p, &five, nil); err == nil {
		t.Error("temp file blocked: written")
	}
	// no built-in settings either
	fakeDefaults(t, fstest.MapFS{})
	if err := SetScanLimits(PathsAt(t.TempDir()), &five, nil); err == nil {
		t.Error("no settings at all: written")
	}
}
