package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/uptrace/bun"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/fset"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Pack: a dataset's findings as stored (fset.Set.Encode).
type Pack struct {
	bun.BaseModel `bun:"table:packs"`

	DatasetID int64  `bun:",pk"`
	Parts     []byte `bun:",notnull"`
	Items     []byte `bun:",notnull"`
}

// Load: the findings of dir (a run directory or current/), in the order report.LoadFindings reads them, from the
// reports directory's database; the files it doesn't hold as they are now are imported first.
func Load(ctx context.Context, reports, dir string) (*fset.Set, error) {
	db, err := Open(ctx, reports)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }() // read-only use, or committed already
	dss, err := db.sync(ctx, dir)
	if err != nil {
		return nil, err
	}
	b := fset.NewBuilder()
	n := 0
	for _, ds := range dss {
		n += ds.Rows
	}
	b.Grow(n)
	lazy := &fset.Lazy{Fetch: func(refs []int64) (map[int64]string, error) { return descriptions(reports, refs) }}
	for _, ds := range dss {
		var p Pack
		if err := db.NewSelect().Model(&p).Where("dataset_id = ?", ds.ID).Scan(ctx); err != nil {
			return nil, err
		}
		if err := b.AddEncoded(p.Parts, p.Items, lazy, ds.ID); err != nil {
			return nil, err
		}
	}
	return b.Set(), nil
}

// descriptions: the CVE descriptions refs name (dataset << 32 | index); a dataset dropped since gives none.
func descriptions(reports string, refs []int64) (map[int64]string, error) {
	ctx := context.Background()
	db, err := Open(ctx, reports)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }() // read-only
	q, err := db.PrepareContext(ctx, "SELECT text FROM descs WHERE dataset_id = ? AND idx = ?")
	if err != nil {
		return nil, err
	}
	defer func() { _ = q.Close() }()
	out := map[int64]string{}
	for _, r := range refs {
		var t string
		switch err := q.QueryRowContext(ctx, r>>32, r&(1<<32-1)).Scan(&t); {
		case err == nil:
			out[r] = t
		case !errors.Is(err, sql.ErrNoRows):
			return nil, err
		}
	}
	return out, nil
}

// Sync imports what the database doesn't hold of dir's findings as the files are now; nothing is kept in memory.
// A dashboard runs it in the background on start, so the first look at an environment does not wait for it.
func Sync(ctx context.Context, reports, dir string) error {
	db, err := Open(ctx, reports)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }() // read-only use, or committed already
	_, err = db.sync(ctx, dir)
	return err
}

// SyncHost imports host's findings file in dir unless the database holds it as it is: call it right after
// writing the file. It is read one finding at a time.
func SyncHost(ctx context.Context, reports, dir, host string) error {
	hfs, err := report.HostFiles(dir)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(hfs, func(hf report.HostFile) bool { return hf.Host == host })
	if i < 0 {
		return nil // not what dir holds (an older run's single file is there): nothing to keep in step with
	}
	mtime, size, ok := stat(hfs[i].Path)
	if !ok {
		return nil
	}
	db, err := Open(ctx, reports)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }() // committed already
	have, err := db.datasets(ctx, dir)
	if err != nil {
		return err
	}
	if !fresh(have[host], mtime, size) {
		if err := db.copyOrImport(ctx, &Dataset{Dir: dir, Host: host, Mtime: mtime, Size: size}, hfs[i].Path); err != nil {
			return err
		}
	}
	return db.touch(ctx, dir)
}

// sync brings dir's datasets in step with its findings files and returns them, in the files' order.
func (db *DB) sync(ctx context.Context, dir string) ([]*Dataset, error) {
	hfs, err := report.HostFiles(dir)
	if err != nil {
		return nil, err
	}
	have, err := db.datasets(ctx, dir)
	if err != nil {
		return nil, err
	}
	var out []*Dataset
	for _, hf := range hfs {
		mtime, size, ok := stat(hf.Path)
		if !ok {
			continue
		}
		ds := have[hf.Host]
		delete(have, hf.Host)
		if !fresh(ds, mtime, size) {
			ds = &Dataset{Dir: dir, Host: hf.Host, Mtime: mtime, Size: size}
			if err := db.copyOrImport(ctx, ds, hf.Path); err != nil {
				return nil, err
			}
		}
		out = append(out, ds)
	}
	if len(have) > 0 { // hosts whose file is gone
		var drop []int64
		for _, ds := range have {
			drop = append(drop, ds.ID)
		}
		if _, err := db.NewDelete().Model((*Dataset)(nil)).Where("id IN (?)", bun.List(drop)).Exec(ctx); err != nil {
			return nil, err
		}
	}
	return out, db.touch(ctx, dir)
}

// copyOrImport stores the file at path as ds: copied from a dataset of the same file elsewhere (current/ links
// a run's host file), imported otherwise.
func (db *DB) copyOrImport(ctx context.Context, ds *Dataset, path string) error {
	var src Dataset
	err := db.NewSelect().Model(&src).Where("host = ? AND mtime = ? AND size = ? AND version = ? AND dir != ?",
		ds.Host, ds.Mtime, ds.Size, Version, ds.Dir).Limit(1).Scan(ctx)
	switch {
	case err == nil:
		return db.copyFrom(ctx, ds, &src)
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	b := fset.NewBuilder()
	var aerr error
	if err := report.EachFindingIn(path, func(f *finding.Finding) {
		if aerr == nil {
			aerr = b.Add(f)
		}
	}); err != nil {
		return err
	}
	if aerr != nil {
		return aerr
	}
	return db.put(ctx, ds, b.Set())
}

// copyFrom stores src's pack as ds.
func (db *DB) copyFrom(ctx context.Context, ds, src *Dataset) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := replace(ctx, tx, ds, src.Rows); err != nil {
		return err
	}
	for _, q := range []string{
		`INSERT INTO packs (dataset_id, parts, items) SELECT ?, parts, items FROM packs WHERE dataset_id = ?`,
		`INSERT INTO descs (dataset_id, idx, text) SELECT ?, idx, text FROM descs WHERE dataset_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, ds.ID, src.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// put stores s as ds (Dir, Host, Mtime, Size), replacing what was there.
func (db *DB) put(ctx context.Context, ds *Dataset, s *fset.Set) error {
	parts, items, descs, err := s.Encode()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := replace(ctx, tx, ds, s.Len()); err != nil {
		return err
	}
	if _, err := tx.NewInsert().Model(&Pack{DatasetID: ds.ID, Parts: parts, Items: items}).Exec(ctx); err != nil {
		return err
	}
	ins, err := tx.PrepareContext(ctx, "INSERT INTO descs (dataset_id, idx, text) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { _ = ins.Close() }()
	for i, d := range descs {
		if d != "" {
			if _, err := ins.ExecContext(ctx, ds.ID, i, d); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// replace drops what the database holds of ds's file and inserts ds (its ID set) with rows findings.
func replace(ctx context.Context, tx bun.Tx, ds *Dataset, rows int) error {
	if _, err := tx.NewDelete().Model((*Dataset)(nil)).Where("dir = ? AND host = ?", ds.Dir, ds.Host).Exec(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ds.ID, ds.Version, ds.Rows, ds.ImportedAt, ds.UsedAt = 0, Version, rows, now, now
	_, err := tx.NewInsert().Model(ds).Exec(ctx)
	return err
}
