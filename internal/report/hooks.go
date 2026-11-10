package report

// OnCurrent, when set, gets the hosts whose current/ file changed (linked, copied or merged) after UpdateCurrent:
// the CLI brings reports/kanareika.db (package store) in step there, once per scan rather than per host while
// hosts are scanned. report itself does not depend on the store.
var OnCurrent func(dir string, hosts []string)
