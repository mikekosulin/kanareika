package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// brokenEnv: a copy of the fixture environment (legacy single files), split into host files, with one host file of
// the newest run not gzip at all.
func brokenEnv(t *testing.T) (env, run string) {
	t.Helper()
	env = filepath.Join(t.TempDir(), "acme", "production")
	if err := os.CopyFS(env, os.DirFS("testdata/fixture/env/acme-production")); err != nil {
		t.Fatal(err)
	}
	if err := MigrateEnv(env); err != nil {
		t.Fatal(err)
	}
	runs := runDirs(env)
	for i := len(runs) - 1; i >= 0; i-- { // the newest run with a host file
		hfs, err := HostFiles(runs[i])
		if err != nil {
			t.Fatal(err)
		}
		for _, hf := range hfs {
			if err := os.WriteFile(hf.Path, []byte("not gzip"), 0o644); err != nil {
				t.Fatal(err)
			}
			return env, runs[i]
		}
	}
	t.Fatal("no host file")
	return
}

// TestBrokenHostFile: a run whose host file doesn't read stops what reads it with an error, nothing half written:
// its view, the fold into current/, the findings of the run.
func TestBrokenHostFile(t *testing.T) {
	env, run := brokenEnv(t)
	meta, err := LoadMeta(run)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildViewDir(run, meta, ""); err == nil {
		t.Error("a view built over a broken file")
	}
	if _, err := LoadFindings(run); err == nil {
		t.Error("findings read from a broken file")
	}
	if err := EachFinding(run, func(*finding.Finding) {}); err == nil {
		t.Error("each finding of a broken file")
	}
	if _, err := UpdateCurrent(env, false, true); err == nil {
		t.Error("current/ folded from a broken file")
	}
}
