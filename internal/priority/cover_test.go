package priority

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
)

// truncated: a gzip stream with a valid header whose body is cut off.
func truncated(s string) []byte {
	b := gz(s)
	return b[:len(b)-8]
}

func TestFeedsDirNoCacheDir(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("LocalAppData", "")
	want := filepath.Join(os.TempDir(), "kanareika", "feeds")
	if d := FeedsDir(); d != want {
		t.Fatalf("FeedsDir() = %q, want %q", d, want)
	}
}

func TestLoadPolicyErrors(t *testing.T) {
	p := config.PathsAt(t.TempDir())
	must(t, os.MkdirAll(p.Policy, 0o755))
	must(t, os.WriteFile(filepath.Join(p.Policy, "priority.yml"), []byte("rules: 5\n"), 0o644))
	if _, err := LoadPolicy(p); err == nil || !strings.HasPrefix(err.Error(), "priority.yml: rules") {
		t.Fatalf("bad local policy: %v", err)
	}

	old := policyFile
	t.Cleanup(func() { policyFile = old })
	policyFile = func(config.Paths, string) ([]byte, error) { return nil, os.ErrPermission }
	if _, err := LoadPolicy(p); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("read error: %v", err)
	}
}

func TestParsePolicyBadYAML(t *testing.T) {
	if _, err := ParsePolicy([]byte("rules: [unclosed")); err == nil {
		t.Fatal("bad YAML accepted")
	}
}

// TestUpdateFeedsWriteErrors: kev.json / epss.json cannot be stored (their temp names are taken by directories).
func TestUpdateFeedsWriteErrors(t *testing.T) {
	srv := feedServer(t, map[string][]byte{"/kev.json": []byte(kevJSON), "/epss.csv.gz": gz(epssCSV)})
	pol := &Policy{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"}
	for _, name := range []string{"kev.json", "epss.json"} {
		dir := t.TempDir()
		t.Setenv("KANAREIKA_FEEDS_DIR", dir)
		must(t, os.Mkdir(filepath.Join(dir, name+".tmp"), 0o755))
		st, err := UpdateFeeds(context.Background(), pol)
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if name == "epss.json" && st.KEV != 2 {
			t.Fatalf("KEV stored before the EPSS failure: %+v", st)
		}
		if _, err := os.Stat(filepath.Join(dir, "updated")); err == nil {
			t.Fatalf("%s: updated written after a failure", name)
		}
	}
}

func TestTruncatedGzip(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	srv := feedServer(t, map[string][]byte{"/kev.json": []byte(kevJSON), "/cut.gz": truncated(epssCSV + strings.Repeat("CVE-2026-0009,0.1,0.2\n", 50))})
	_, err := UpdateFeeds(context.Background(), &Policy{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/cut.gz"})
	if !errors.Is(err, io.ErrUnexpectedEOF) || !strings.HasPrefix(err.Error(), "EPSS: ") {
		t.Fatalf("truncated EPSS: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "dbip-city.mmdb")
	if err := download(context.Background(), srv.URL+"/cut.gz", dest); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated download: %v", err)
	}
	for _, p := range []string{dest, dest + ".tmp"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", p, err)
		}
	}
}

func TestInOtherTypes(t *testing.T) {
	for _, v := range []any{5.0, true, nil, map[string]any{"a": 1}} {
		if in("a", v) {
			t.Errorf("in(a, %v) = true", v)
		}
	}
	if !in("ssh", "openssh-server") || in(1.0, "1") || !in("x", []any{"y", "x"}) {
		t.Fatal("in() basics")
	}
}
