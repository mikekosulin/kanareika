package trivy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNoUserCacheDir: without TRIVY_CACHE_DIR and a home, there is no cache dir and no DB is seen.
func TestNoUserCacheDir(t *testing.T) {
	t.Setenv("TRIVY_CACHE_DIR", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", "")
	if d := CacheDir(); d != "" {
		t.Fatal(d)
	}
	for _, d := range DBStatus() {
		if d.Dir != "" || !d.Updated.IsZero() || !d.Next.IsZero() || !d.Outdated(time.Now()) {
			t.Fatal(d)
		}
	}
}

func TestNextUpdateAndOutdated(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("TRIVY_CACHE_DIR", cache)
	must(t, os.MkdirAll(filepath.Join(cache, "db"), 0o755))
	must(t, os.WriteFile(filepath.Join(cache, "db", "metadata.json"),
		[]byte(`{"UpdatedAt":"2026-11-01T00:00:00Z","NextUpdate":"2026-11-02T00:00:00Z"}`), 0o644))
	st := DBStatus()
	if st[0].Next.Format(time.RFC3339) != "2026-11-02T00:00:00Z" || !st[1].Next.IsZero() {
		t.Fatal(st)
	}
	before := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	after := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	if st[0].Outdated(before) || !st[0].Outdated(after) {
		t.Fatal("db: fresh before NextUpdate, outdated after")
	}
	if !st[1].Outdated(before) {
		t.Fatal("java-db never downloaded: outdated")
	}
	if (DBInfo{Updated: before}).Outdated(after) {
		t.Fatal("unknown NextUpdate: not outdated")
	}
}

// TestMissingBinary: a KANAREIKA_TRIVY that does not exist is a plain error, not a trivy Error.
func TestMissingBinary(t *testing.T) {
	t.Setenv("KANAREIKA_TRIVY", filepath.Join(t.TempDir(), "missing"))
	_, err := Run(context.Background(), []string{"fs"}, filepath.Join(t.TempDir(), "out.json"), time.Minute)
	var te *Error
	if err == nil || errors.As(err, &te) || !strings.HasPrefix(err.Error(), "KANAREIKA_TRIVY") {
		t.Fatal(err)
	}
	if v := Version(context.Background()); v != "?" {
		t.Fatal(v)
	}
}

func TestRunEdges(t *testing.T) {
	ctx := context.Background()
	calls := filepath.Join(t.TempDir(), "args")
	t.Setenv("CALLS", calls)
	// creates an empty report and records its arguments
	fake(t, `echo "$@" > "$CALLS"; while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done; : > "$out"`)

	prepared.Store(true)
	t.Cleanup(func() { prepared.Store(false) })
	out := filepath.Join(t.TempDir(), "trivy-os.json")
	data, err := Run(ctx, []string{"rootfs", "/"}, out, time.Minute)
	must(t, err)
	if string(data) != "{}" {
		t.Fatal(string(data))
	}
	args, _ := os.ReadFile(calls)
	if !strings.Contains(string(args), "--skip-db-update --skip-java-db-update") {
		t.Fatal(string(args))
	}

	// the .gz cannot be created: a directory is in the way
	out2 := filepath.Join(t.TempDir(), "trivy-img.json")
	must(t, os.Mkdir(out2+".gz", 0o755))
	if _, err := Run(ctx, []string{"image", "acme/web:1"}, out2, time.Minute); err == nil {
		t.Fatal("gzip into a directory must fail")
	}

	// trivy exits 0 without writing a report
	fake(t, `exit 0`)
	if _, err := Run(ctx, []string{"fs"}, filepath.Join(t.TempDir(), "none.json"), time.Minute); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestVersionBadOutput(t *testing.T) {
	ctx := context.Background()
	fake(t, `echo not-json`)
	if v := Version(ctx); v != "?" {
		t.Fatal(v)
	}
	fake(t, `echo '{"Other":"x"}'`)
	if v := Version(ctx); v != "?" {
		t.Fatal(v)
	}
}

// TestPrepareCancelled: a cancelled context stops at the first attempt and is returned as is.
func TestPrepareCancelled(t *testing.T) {
	t.Setenv("TRIVY_CACHE_DIR", t.TempDir())
	t.Setenv("TRIVY_DB_REPOSITORY", "")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", "")
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("CALLS", calls)
	fake(t, `echo x >> "$CALLS"; exit 0`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var logs []string
	if err := Prepare(ctx, func(f string, a ...any) { logs = append(logs, f) }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(calls); !os.IsNotExist(err) || len(logs) != 0 {
		t.Fatal("trivy must not run with a cancelled context", logs)
	}
}

func TestCVSSUnmarshalEdges(t *testing.T) {
	var c CVSS
	must(t, c.UnmarshalJSON([]byte(`null`)))
	if c.Sources != nil || len(c.Vectors) != 0 {
		t.Fatal(c)
	}
	if err := c.UnmarshalJSON([]byte(`[1]`)); err == nil || err.Error() != "CVSS: object expected" {
		t.Fatal(err)
	}
	if err := c.UnmarshalJSON([]byte(``)); err == nil {
		t.Fatal("empty input")
	}
	if err := c.UnmarshalJSON([]byte(`{1:{}}`)); err == nil {
		t.Fatal("non-string key")
	}
	if err := c.UnmarshalJSON([]byte(`{"nvd":1}`)); err == nil {
		t.Fatal("vectors must be an object")
	}
	if _, err := ParseReport([]byte(`{"Results":[{"Vulnerabilities":[{"CVSS":{"nvd":"x"}}]}]}`)); err == nil ||
		!strings.HasPrefix(err.Error(), "trivy report: ") {
		t.Fatal(err)
	}
}
