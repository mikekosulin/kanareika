package trivy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// withBuild: pretend this binary was built with (or without) trivy linked in.
func withBuild(t *testing.T, deps []*debug.Module, ok bool) {
	t.Helper()
	old := buildInfo
	buildInfo = func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Deps: deps}, ok }
	t.Cleanup(func() { buildInfo = old })
}

func TestEmbedded(t *testing.T) {
	withBuild(t, nil, false)
	if v := Embedded(); v != "" {
		t.Fatal(v)
	}
	withBuild(t, []*debug.Module{{Path: "x/y", Version: "v1.0.0"}}, true)
	if v := Embedded(); v != "" {
		t.Fatal(v)
	}
	withBuild(t, []*debug.Module{{Path: "x/y", Version: "v1.0.0"}, {Path: EngineModule, Version: "v0.75.0"}}, true)
	if v := Embedded(); v != "0.75.0" {
		t.Fatal(v)
	}
	withBuild(t, []*debug.Module{{Path: EngineModule, Version: "v0.75.0", Replace: &debug.Module{Version: "v0.75.1"}}}, true)
	if v := Embedded(); v != "0.75.1" {
		t.Fatal(v)
	}
}

func TestBinary(t *testing.T) {
	t.Setenv("KANAREIKA_TRIVY", "")
	withBuild(t, nil, true)
	if _, _, err := Binary(); err == nil || !strings.Contains(err.Error(), "no embedded trivy") {
		t.Fatal(err)
	}

	withBuild(t, []*debug.Module{{Path: EngineModule, Version: "v0.75.0"}}, true)
	old := executable
	t.Cleanup(func() { executable = old })
	executable = func() (string, error) { return "/opt/kanareika", nil }
	bin, prefix, err := Binary()
	if err != nil || bin != "/opt/kanareika" || len(prefix) != 1 || prefix[0] != EngineCommand {
		t.Fatal(bin, prefix, err)
	}
	executable = func() (string, error) { return "", errors.New("gone") }
	if _, _, err := Binary(); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Fatal(err)
	}

	// an explicit binary wins, and must exist
	t.Setenv("KANAREIKA_TRIVY", filepath.Join(t.TempDir(), "missing"))
	if _, _, err := Binary(); err == nil || !strings.HasPrefix(err.Error(), "KANAREIKA_TRIVY") {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "trivy")
	must(t, os.WriteFile(p, nil, 0o755))
	t.Setenv("KANAREIKA_TRIVY", p)
	if bin, prefix, err := Binary(); err != nil || bin != p || prefix != nil {
		t.Fatal(bin, prefix, err)
	}
}

// TestSelfExec: the embedded trivy is kanareika itself, started with the hidden command first.
func TestSelfExec(t *testing.T) {
	ctx := context.Background()
	t.Setenv("KANAREIKA_TRIVY", "")
	withBuild(t, []*debug.Module{{Path: EngineModule, Version: "v0.75.0"}}, true)
	fake(t, `[ "$1" = __trivy ] || exit 9; shift
while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done; echo '{"Results":[]}' > "$out"`)
	self := os.Getenv("KANAREIKA_TRIVY")
	t.Setenv("KANAREIKA_TRIVY", "")
	old := executable
	t.Cleanup(func() { executable = old })
	executable = func() (string, error) { return self, nil }
	if _, err := Run(ctx, []string{"sbom", "x"}, filepath.Join(t.TempDir(), "o.json"), time.Minute); err != nil {
		t.Fatal(err)
	}
	// the embedded version comes from the build, without starting anything
	executable = func() (string, error) { return "", errors.New("must not run") }
	if v := Version(ctx); v != "0.75.0" {
		t.Fatal(v)
	}
}

func TestOfflineAndStatus(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("TRIVY_CACHE_DIR", cache)
	if CacheDir() != cache {
		t.Fatal(CacheDir())
	}
	prepared.Store(false)
	t.Cleanup(func() { prepared.Store(false) })
	if err := PrepareOffline(nil); !errors.Is(err, ErrNoDB) || !strings.Contains(err.Error(), "trivy db") {
		t.Fatal(err)
	}
	for _, d := range DBStatus() {
		if !d.Updated.IsZero() || d.Dir != filepath.Join(cache, d.Name) {
			t.Fatal(d)
		}
	}
	must(t, os.MkdirAll(filepath.Join(cache, "db"), 0o755))
	must(t, os.WriteFile(filepath.Join(cache, "db", "metadata.json"), []byte(`{"UpdatedAt":"2026-11-01T19:08:08Z"}`), 0o644))
	if err := PrepareOffline(nil); !errors.Is(err, ErrNoDB) || !strings.Contains(err.Error(), "java-db") {
		t.Fatal(err)
	}
	must(t, os.MkdirAll(filepath.Join(cache, "java-db"), 0o755))
	must(t, os.WriteFile(filepath.Join(cache, "java-db", "metadata.json"), []byte(`{"DownloadedAt":"2026-11-02T00:00:00Z"}`), 0o644))
	var logs []string
	must(t, PrepareOffline(func(f string, a ...any) { logs = append(logs, f) }))
	if !prepared.Load() || len(logs) != 2 {
		t.Fatal(logs)
	}
	st := DBStatus()
	if st[0].Name != "db" || st[0].Updated.Format(time.RFC3339) != "2026-11-01T19:08:08Z" ||
		st[1].Name != "java-db" || st[1].Updated.Format(time.RFC3339) != "2026-11-02T00:00:00Z" {
		t.Fatal(st)
	}
	// a broken metadata.json counts as no DB
	must(t, os.WriteFile(filepath.Join(cache, "java-db", "metadata.json"), []byte(`{`), 0o644))
	if DBStatus()[1].Updated != (time.Time{}) {
		t.Fatal("broken metadata")
	}
}
