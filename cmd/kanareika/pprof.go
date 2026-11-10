package main

import (
	"net/http"
	_ "net/http/pprof" // KANAREIKA_PPROF only
	"os"
)

// KANAREIKA_PPROF=127.0.0.1:6060 serves Go's profiles (/debug/pprof/) while kanareika runs, for measuring a
// scan or a dashboard on real data. The embedded trivy is a child process and does not inherit it.
func init() {
	if addr := os.Getenv("KANAREIKA_PPROF"); addr != "" && (len(os.Args) < 2 || os.Args[1] != "__trivy") {
		go func() { _ = http.ListenAndServe(addr, nil) }()
	}
}
