package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// datasets: one per imported findings file: a host's file of a run directory or current/ (host "" for the single
// file of a run written before 0.6). packs: its findings as package fset encodes them: the distinct parts (JSON)
// and the items as indexes into them. descs: the descriptions of its CVE parts (by index), read only for a
// node's details.
func init() {
	All.MustRegister(func(ctx context.Context, db *bun.DB) error {
		for _, q := range []string{
			`CREATE TABLE datasets (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				dir         TEXT    NOT NULL,
				host        TEXT    NOT NULL,
				mtime       INTEGER NOT NULL,
				size        INTEGER NOT NULL,
				version     INTEGER NOT NULL,
				rows        INTEGER NOT NULL,
				imported_at TEXT    NOT NULL,
				used_at     TEXT    NOT NULL,
				UNIQUE (dir, host)
			)`,
			`CREATE INDEX datasets_file ON datasets (host, mtime, size)`,
			`CREATE TABLE packs (
				dataset_id INTEGER PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
				parts      BLOB    NOT NULL,
				items      BLOB    NOT NULL
			)`,
			`CREATE TABLE descs (
				dataset_id INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
				idx        INTEGER NOT NULL,
				text       TEXT    NOT NULL,
				PRIMARY KEY (dataset_id, idx)
			) WITHOUT ROWID`,
		} {
			if _, err := db.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		for _, t := range []string{"descs", "packs", "datasets"} {
			if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+t); err != nil {
				return err
			}
		}
		return nil
	})
}
