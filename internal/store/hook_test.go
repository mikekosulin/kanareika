package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/migrate"

	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/store/migrations"
)

// failQuery fails the first query whose SQL holds match: before it runs (the query itself fails), or after it
// (cancel: what the code does next on the same context fails: a transaction begun, a statement prepared).
type failQuery struct {
	match  string
	after  bool
	cancel context.CancelFunc
	hit    bool
}

func (h *failQuery) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	if !h.after && !h.hit && strings.Contains(e.Query, h.match) {
		h.hit = true
		c, cancel := context.WithCancel(ctx)
		cancel()
		return c
	}
	return ctx
}

func (h *failQuery) AfterQuery(_ context.Context, e *bun.QueryEvent) {
	if h.after && !h.hit && strings.Contains(e.Query, h.match) {
		h.hit = true
		h.cancel()
	}
}

func hook(t *testing.T, h *failQuery) {
	t.Helper()
	testHook = h
	t.Cleanup(func() { testHook = nil })
}

func canceled(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("%s: %v, want the query's failure", what, err)
	}
}

// TestReadsThatFail: each read and each step of a write that the database fails gives that failure back; the next
// load without the fault reads the findings as they are.
func TestReadsThatFail(t *testing.T) {
	for _, c := range []struct {
		name, match string
		after       bool
		setup       func(t *testing.T, reports, run, cur string) string // the directory to load
	}{
		{"the pack", `FROM "packs"`, false, loaded},
		{"the datasets of a directory", `WHERE (dir = `, false, fresh0},
		{"the source of a copy", `AND mtime = `, false, linked},
		{"begin the copy", `AND mtime = `, true, linked},
		{"begin an import", `AND mtime = `, true, fresh0},
		{"prepare the descriptions", `INSERT INTO "packs"`, true, fresh0},
		{"drop a gone host", `WHERE (id IN (`, false, goneHost},
		{"the bookkeeping", `ORDER BY "used_at" DESC`, false, fresh0},
	} {
		t.Run(c.name, func(t *testing.T) {
			reports := t.TempDir()
			run := filepath.Join(reports, "acme", "production", "2026-11-10_120000")
			cur := filepath.Join(reports, "acme", "production", "current")
			dir := c.setup(t, reports, run, cur)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := &failQuery{match: c.match, after: c.after, cancel: cancel}
			hook(t, h)
			_, err := Load(ctx, reports, dir)
			if !h.hit {
				t.Fatalf("no query with %q", c.match)
			}
			canceled(t, "load", err)
			testHook = nil
			if d, err := Load(context.Background(), reports, dir); err != nil || d.Len() == 0 {
				t.Fatalf("after the fault: %v %v", d, err)
			}
		})
	}
}

// fresh0: a directory never read.
func fresh0(t *testing.T, _, run, _ string) string {
	writeFindings(t, run, sample())
	return run
}

// loaded: a directory read once (its pack is in the database).
func loaded(t *testing.T, reports, run, _ string) string {
	writeFindings(t, run, sample())
	if _, err := Load(context.Background(), reports, run); err != nil {
		t.Fatal(err)
	}
	return run
}

// linked: current/ with the run's file hard-linked in, the run read once: current/ is a copy.
func linked(t *testing.T, reports, run, cur string) string {
	loaded(t, reports, run, cur)
	if err := os.MkdirAll(cur, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(run, "findings.json.gz"), filepath.Join(cur, "findings.json.gz")); err != nil {
		t.Skip("no hard links here:", err)
	}
	return cur
}

// goneHost: per-host files read once, then one host's file removed.
func goneHost(t *testing.T, reports, run, _ string) string {
	fs := sample()
	for _, h := range []string{"web-01", "web-02"} {
		var mine = fs[:0:0]
		for _, f := range fs {
			if f.Host == h {
				mine = append(mine, f)
			}
		}
		writeFindings(t, filepath.Join(run, "hosts", h), mine)
	}
	if _, err := Load(context.Background(), reports, run); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(run, "hosts", "web-02")); err != nil {
		t.Fatal(err)
	}
	return run
}

// TestDescriptionsThatFail: the query for descriptions failing is the error of the fetch.
func TestDescriptionsThatFail(t *testing.T) {
	reports := t.TempDir()
	if _, err := Open(context.Background(), reports); err != nil {
		t.Fatal(err)
	}
	hook(t, &failQuery{match: `FROM "descs"`})
	_, err := descriptions(reports, []int64{1<<32 | 2})
	canceled(t, "descriptions", err)
}

// TestFileGoneMeanwhile: a host file listed and gone by the time it is read is left out, not an error.
func TestFileGoneMeanwhile(t *testing.T) {
	reports := t.TempDir()
	dir := filepath.Join(reports, "acme", "production", "current")
	writeFindings(t, dir, sample())
	hostFiles = func(dir string) ([]report.HostFile, error) {
		return []report.HostFile{{Host: "gone", Path: filepath.Join(dir, "hosts", "gone", "findings.json.gz")}}, nil
	}
	t.Cleanup(func() { hostFiles = report.HostFiles })
	d, err := Load(context.Background(), reports, dir)
	if err != nil || d.Len() != 0 {
		t.Fatalf("%v %v", d, err)
	}
}

// TestRollbackThatFails: a migration's way down stops at the first table it can't drop.
func TestRollbackThatFails(t *testing.T) {
	ctx := context.Background()
	hook(t, &failQuery{match: "DROP TABLE IF EXISTS descs"})
	db, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := migrate.NewMigrator(db.DB, migrations.All).Rollback(ctx); err == nil {
		t.Fatal("rolled back")
	}
}

// TestMigrateLockFails: a new database whose write lock can't be taken fails that open; Open makes it again.
func TestMigrateLockFails(t *testing.T) {
	h := &failQuery{match: "BEGIN IMMEDIATE"}
	hook(t, h)
	db, err := Open(context.Background(), t.TempDir())
	if err != nil || !h.hit {
		t.Fatalf("%v (lock asked for: %v)", err, h.hit)
	}
	_ = db.Close()
}
