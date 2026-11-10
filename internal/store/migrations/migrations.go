// Package migrations: the schema of reports/kanareika.db, one Go file per change, applied in name order by
// bun's migrator when the database is opened. A migration is never edited after a release: a schema change is a
// new file (YYYYMMDDHHMMSS_what.go) with plain SQL, so the schema does not move when a Go model does.
package migrations

import "github.com/uptrace/bun/migrate"

// All: every migration, registered by the files of this package.
var All = migrate.NewMigrations()
