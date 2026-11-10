package cli

import (
	"os"
	"runtime/debug"
)

// softMemory: the soft memory limit of kanareika's own process (web, tui, mcp, scan), unless GOMEMLIMIT says
// otherwise. Readers hold an environment compactly (package fset: tens of megabytes for a million findings), a
// scan streams its findings (tens of megabytes live); both make much short-lived garbage, and with the limit the
// collector returns it promptly instead of letting the heap grow to twice what is live. The embedded trivy runs
// in a child process of its own and is not limited by it.
const softMemory = 160 << 20

func limitMemory() {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(softMemory)
	}
}
