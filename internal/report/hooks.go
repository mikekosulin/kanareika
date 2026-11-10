package report

// Hooks the CLI sets to keep reports/kanareika.db (package store) in step with the findings files as they are
// written; report itself does not depend on the store.
var (
	// OnHost: a host's findings file in dir (a run, or current/) was just written; the store reads it (streamed).
	OnHost func(dir, host string)
	// OnCurrent gets the hosts whose current/ file changed (linked, copied or merged) after UpdateCurrent.
	OnCurrent func(dir string, hosts []string)
)
