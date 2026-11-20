//go:build !unix

package trivy

import (
	"testing"
	"time"
)

// atime: not checked here: Windows may set access times itself (last-access updates, virus scanners reading new
// files).
func atime(*testing.T, string) (time.Time, bool) { return time.Time{}, false }
