package cli

import (
	"math"
	"os"
	"runtime/debug"
	"sync"
)

// readerMemory: the soft memory limit of the processes that stay up and read reports (web, tui, mcp), unless
// GOMEMLIMIT says otherwise. They hold an environment compactly (package fset: tens of megabytes for a million
// findings) and make much short-lived garbage answering; with the limit the collector returns it promptly
// instead of letting the heap grow to twice what is live. A scan started from the dashboard lifts it while it
// runs (scanning needs more).
const readerMemory = 160 << 20

var memLimit struct {
	sync.Mutex
	on    bool // a reader set it
	scans int  // scans running in this process
}

func limitReaderMemory() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	memLimit.Lock()
	defer memLimit.Unlock()
	memLimit.on = true
	if memLimit.scans == 0 {
		debug.SetMemoryLimit(readerMemory)
	}
}

// scanning lifts the reader limit until the returned func is called.
func scanning() (done func()) {
	memLimit.Lock()
	defer memLimit.Unlock()
	memLimit.scans++
	if memLimit.on {
		debug.SetMemoryLimit(math.MaxInt64)
	}
	return func() {
		memLimit.Lock()
		defer memLimit.Unlock()
		if memLimit.scans--; memLimit.scans == 0 && memLimit.on {
			debug.SetMemoryLimit(readerMemory)
		}
	}
}
