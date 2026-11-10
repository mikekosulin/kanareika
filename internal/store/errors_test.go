package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/uptrace/bun/migrate"

	"github.com/mikekosulin/kanareika/internal/store/migrations"
)

// fail makes the database refuse one kind of write: a trigger raises "boom" on op ("INSERT", "UPDATE", "DELETE") of
// table, as a full disk or a locked file would. The tables keep their shape, so Open still takes the database.
func fail(t *testing.T, reports, table, op string) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, reports)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	q := "CREATE TRIGGER boom_" + strings.ToLower(table+"_"+op) + " BEFORE " + op + " ON " + table + " BEGIN SELECT RAISE(ABORT, 'boom'); END"
	if _, err := db.ExecContext(ctx, q); err != nil {
		t.Fatal(err)
	}
}

func boom(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("%s: %v, want the database's refusal", what, err)
	}
}

// TestWritesThatFail: an import, a copy of a linked file, a re-import and the bookkeeping after a read each give the
// database's error when it refuses the write, and leave nothing half done: the next read without the fault works.
func TestWritesThatFail(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		table, op string
		again     bool // a re-import: the file was read before and changed since (a DELETE fires only on a row)
	}{
		{"packs", "INSERT", false}, {"descs", "INSERT", false}, {"datasets", "INSERT", false}, {"datasets", "DELETE", true},
	} {
		t.Run(c.table+"_"+c.op, func(t *testing.T) {
			reports := t.TempDir()
			dir := filepath.Join(reports, "acme", "production", "current")
			writeFindings(t, dir, sample())
			if c.again {
				if _, err := Load(ctx, reports, dir); err != nil {
					t.Fatal(err)
				}
				writeFindings(t, dir, sample()[:2])
			}
			fail(t, reports, c.table, c.op)
			_, err := Load(ctx, reports, dir)
			boom(t, "load", err)
			boom(t, "sync", Sync(ctx, reports, dir))
		})
	}
	// the bookkeeping after a read: marking the datasets used
	reports := t.TempDir()
	dir := filepath.Join(reports, "acme", "production", "current")
	writeFindings(t, dir, sample())
	if _, err := Load(ctx, reports, dir); err != nil {
		t.Fatal(err)
	}
	fail(t, reports, "datasets", "UPDATE")
	_, err := Load(ctx, reports, dir)
	boom(t, "touch", err)
}

// TestCopyThatFails: a run's file hard-linked into current/ is copied inside the database, not imported again; when
// the copy is refused, the error comes back.
func TestCopyThatFails(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct{ table, op string }{{"packs", "INSERT"}, {"descs", "INSERT"}, {"datasets", "INSERT"}} {
		t.Run(c.table+"_"+c.op, func(t *testing.T) {
			reports := t.TempDir()
			run := filepath.Join(reports, "acme", "production", "2026-11-10_120000")
			cur := filepath.Join(reports, "acme", "production", "current")
			writeFindings(t, run, sample())
			if _, err := Load(ctx, reports, run); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(cur, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(run, "findings.json.gz"), filepath.Join(cur, "findings.json.gz")); err != nil {
				t.Skip("no hard links here:", err)
			}
			fail(t, reports, c.table, c.op)
			_, err := Load(ctx, reports, cur)
			boom(t, "copy", err)
		})
	}
}

// TestFilesThatFail: a findings file that isn't one, a run directory that can't be listed and a reports directory
// that can't be made each give their error, not an empty set.
func TestFilesThatFail(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	dir := filepath.Join(reports, "acme", "production", "current")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "findings.json.gz"), []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, reports, dir); err == nil {
		t.Fatal("a broken findings file read as findings")
	}
	// hosts/ that is a file: the host files can't be listed (Windows reads it as no directory: no hosts)
	bad := filepath.Join(reports, "acme", "staging", "current")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "hosts"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Sync(ctx, reports, bad); err == nil && runtime.GOOS != "windows" {
		t.Fatal("hosts/ as a file synced")
	}
	// the reports directory is a file: no database
	file := filepath.Join(t.TempDir(), "reports")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, file, dir); err == nil {
		t.Fatal("loaded without a database")
	}
	if err := Sync(ctx, file, dir); err == nil {
		t.Fatal("synced without a database")
	}
	if _, err := descriptions(file, []int64{1}); err == nil {
		t.Fatal("descriptions without a database")
	}
}

// TestBrokenPack: a pack that doesn't decode (a database written by something else) is an error, not findings.
func TestBrokenPack(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	dir := filepath.Join(reports, "acme", "production", "current")
	writeFindings(t, dir, sample())
	if _, err := Load(ctx, reports, dir); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, reports)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE packs SET parts = x'ffffffff00', items = x'0102'"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := Load(ctx, reports, dir); err == nil {
		t.Fatal("a broken pack decoded")
	}
}

// TestDescriptionsOfDroppedDataset: descriptions of a dataset dropped since the set was read are just not there.
func TestDescriptionsOfDroppedDataset(t *testing.T) {
	reports := t.TempDir()
	ds, err := descriptions(reports, []int64{7<<32 | 3})
	if err != nil || len(ds) != 0 {
		t.Fatalf("%v %v", ds, err)
	}
}

// TestMigrationsBothWays: the schema rolls back to nothing and up again; a file that is a database of something else
// (a table of the same name, no migrations recorded) is replaced rather than failing every open.
func TestMigrationsBothWays(t *testing.T) {
	ctx := context.Background()
	reports := t.TempDir()
	db, err := Open(ctx, reports)
	if err != nil {
		t.Fatal(err)
	}
	m := migrate.NewMigrator(db.DB, migrations.All)
	if _, err := m.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.NewRaw("SELECT count(*) FROM sqlite_master WHERE name IN ('datasets', 'packs', 'descs')").Scan(ctx, &n); err != nil || n != 0 {
		t.Fatalf("%d tables left after the rollback (%v)", n, err)
	}
	_ = db.Close()
	dir := filepath.Join(reports, "acme", "production", "current")
	writeFindings(t, dir, sample())
	if d, err := Load(ctx, reports, dir); err != nil || d.Len() != len(sample()) {
		t.Fatalf("%v %v", d, err)
	}
	// someone else's database at our name
	other := t.TempDir()
	sqldb, err := sql.Open("sqlite", Path(other))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.Exec("CREATE TABLE datasets (x TEXT)"); err != nil {
		t.Fatal(err)
	}
	_ = sqldb.Close()
	db, err = Open(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
}
