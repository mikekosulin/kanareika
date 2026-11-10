// Package store keeps the findings of report runs in SQLite, reports/kanareika.db, so the interfaces read them
// without parsing the findings files (over a gigabyte of JSON on a large environment) on every start.
//
// The report files stay the source of truth. Each findings file (one per host: report.HostFiles) is a dataset,
// imported when current/ takes it after a scan (report.OnCurrent: a run's file linked there and already held is
// copied in SQL, not decoded) or when first read, and imported again when it changes, when the import code
// changes (Version) or when the database is missing. Deleting kanareika.db loses nothing.
//
// The database is opened for each operation and closed after it: no file stays open between requests (Windows can
// then delete a reports directory), and a scan and a dashboard in other processes share it through SQLite's locks.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/migrate"
	_ "modernc.org/sqlite" // the pure-Go SQLite driver: no cgo, nothing to install

	"github.com/mikekosulin/kanareika/internal/store/migrations"
)

// File: the database's name in the reports directory.
const File = "kanareika.db"

// Version of the import: rows imported by another version are imported again. Bump it when what is stored per
// finding changes meaning (a precomputed column such as unit) without a schema change.
const Version = 4

// keepRuns: datasets of run directories kept besides current/ ones (the runs looked at most recently).
const keepRuns = 6

// Dataset: one imported findings file.
type Dataset struct {
	bun.BaseModel `bun:"table:datasets"`

	ID         int64  `bun:",pk,autoincrement"`
	Dir        string `bun:",notnull"`
	Host       string `bun:",notnull"`
	Mtime      int64  `bun:",notnull"`
	Size       int64  `bun:",notnull"`
	Version    int    `bun:",notnull"`
	Rows       int    `bun:",notnull"`
	ImportedAt string `bun:",notnull"`
	UsedAt     string `bun:",notnull"`
}

// DB: an open database.
type DB struct {
	*bun.DB
}

// Path: the database of a reports directory.
func Path(reports string) string { return filepath.Join(reports, File) }

// Open opens (creating it if needed) the database of a reports directory and brings its schema up to date. A
// database it can't read (a development build's schema) is deleted and made again: it only caches the files.
func Open(ctx context.Context, reports string) (*DB, error) {
	db, err := open(ctx, reports)
	if err == nil {
		if err = db.check(ctx); err == nil {
			return db, nil
		}
		_ = db.Close()
	}
	for _, sfx := range []string{"", "-wal", "-shm"} {
		if rerr := os.Remove(Path(reports) + sfx); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return nil, err
		}
	}
	return open(ctx, reports)
}

// check: whether the tables read as this version expects.
func (db *DB) check(ctx context.Context) error {
	for _, q := range []string{"SELECT id, dir, host, mtime, size, version, rows, imported_at, used_at FROM datasets LIMIT 0",
		"SELECT dataset_id, parts, items FROM packs LIMIT 0", "SELECT dataset_id, idx, text FROM descs LIMIT 0"} {
		rows, err := db.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		_ = rows.Close()
	}
	return nil
}

func open(ctx context.Context, reports string) (*DB, error) {
	if err := os.MkdirAll(reports, 0o755); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(Path(reports)) +
		"?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)" +
		"&_txlock=immediate"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(1) // one connection: pragmas hold, and SQLite writes one at a time anyway
	db := &DB{bun.NewDB(sqldb, sqlitedialect.New())}
	if err := db.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%s: %w", Path(reports), err)
	}
	return db, nil
}

// migrate applies the migrations this database lacks. Up to date (the usual case), it only reads. Otherwise it
// migrates under SQLite's write lock (BEGIN IMMEDIATE on the one connection), so a scan and a dashboard opening a
// new database at once don't both create it: the second waits, then finds nothing to do.
func (db *DB) migrate(ctx context.Context) error {
	var applied int
	if err := db.NewRaw("SELECT count(*) FROM bun_migrations").Scan(ctx, &applied); err == nil &&
		applied >= len(migrations.All.Sorted()) { // more: a newer kanareika migrated it; its additions are not ours to undo
		return nil
	}
	if _, err := db.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	m := migrate.NewMigrator(db.DB, migrations.All, migrate.WithMarkAppliedOnSuccess(true))
	err := m.Init(ctx)
	if err == nil {
		_, err = m.Migrate(ctx)
	}
	if err != nil {
		_, _ = db.ExecContext(ctx, "ROLLBACK")
		return err
	}
	_, err = db.ExecContext(ctx, "COMMIT")
	return err
}

// stat: what identifies the content of a findings file; ok=false when there is none.
func stat(path string) (mtime, size int64, ok bool) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	return st.ModTime().UnixNano(), st.Size(), true
}

// datasets: dir's datasets by host.
func (db *DB) datasets(ctx context.Context, dir string) (map[string]*Dataset, error) {
	var all []*Dataset
	if err := db.NewSelect().Model(&all).Where("dir = ?", dir).Scan(ctx); err != nil {
		return nil, err
	}
	out := map[string]*Dataset{}
	for _, d := range all {
		out[d.Host] = d
	}
	return out, nil
}

// fresh: whether d holds the file as it is now.
func fresh(d *Dataset, mtime, size int64) bool {
	return d != nil && d.Mtime == mtime && d.Size == size && d.Version == Version
}

// touch marks dir's datasets as just used and drops what is no longer needed: datasets whose file is gone, and
// those of run directories beyond the keepRuns used most recently.
func (db *DB) touch(ctx context.Context, dir string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.NewUpdate().Model((*Dataset)(nil)).Set("used_at = ?", now).Where("dir = ?", dir).Exec(ctx); err != nil {
		return err
	}
	var all []Dataset
	if err := db.NewSelect().Model(&all).Column("id", "dir", "host").Order("used_at DESC", "dir").Scan(ctx); err != nil {
		return err
	}
	runs := map[string]bool{}
	gone := map[string]bool{}
	var drop []int64
	for _, x := range all {
		g, ok := gone[x.Dir]
		if !ok {
			_, err := os.Stat(x.Dir)
			g = errors.Is(err, os.ErrNotExist)
			gone[x.Dir] = g
		}
		if g {
			drop = append(drop, x.ID)
			continue
		}
		if filepath.Base(x.Dir) != "current" {
			if !runs[x.Dir] && len(runs) >= keepRuns {
				drop = append(drop, x.ID)
				continue
			}
			runs[x.Dir] = true
		}
	}
	if len(drop) == 0 {
		return nil
	}
	_, err := db.NewDelete().Model((*Dataset)(nil)).Where("id IN (?)", bun.List(drop)).Exec(ctx)
	return err
}
