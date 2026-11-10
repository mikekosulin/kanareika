package main

import (
	"net/http"
	_ "net/http/pprof" // KANAREIKA_PPROF only
	"os"
)

// KANAREIKA_PPROF=127.0.0.1:6060 serves Go's profiles (/debug/pprof/) while kanareika runs, for measuring a
// scan or a dashboard on real data. The embedded trivy is a child process and does not inherit it.
func init() { servePprof(os.Getenv("KANAREIKA_PPROF"), os.Args) }

// servePprof: the profiles on addr, in the background; false when not asked for (or in the trivy child).
func servePprof(addr string, args []string) bool {
	if addr == "" || len(args) > 1 && args[1] == "__trivy" {
		return false
	}
	go func() { _ = http.ListenAndServe(addr, nil) }()
	return true
}
