package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// sandbox: a fresh KANAREIKA_HOME and caches; nothing of the developer's machine (orgs, reports, DBs) is seen.
func sandbox(t *testing.T) {
	t.Helper()
	t.Setenv("KANAREIKA_HOME", t.TempDir())
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(t.TempDir(), "feeds"))
	t.Setenv("TRIVY_CACHE_DIR", filepath.Join(t.TempDir(), "trivy"))
	t.Setenv("KANAREIKA_TRIVY", "")
	t.Setenv("KANAREIKA_OFFLINE", "")
}

// cli runs the command line and returns the exit code, stdout and stderr.
func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := execute("v9.9.9-test", args, &out, &errb)
	return code, out.String(), errb.String()
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p, s string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(p), 0o755))
	must(t, os.WriteFile(p, []byte(s), 0o644))
}
