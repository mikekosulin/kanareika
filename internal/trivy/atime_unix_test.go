//go:build unix

package trivy

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// atime: the file's last access time; false where it is not checked.
func atime(t *testing.T, path string) (time.Time, bool) {
	t.Helper()
	var st unix.Stat_t
	must(t, unix.Stat(path, &st))
	return time.Unix(st.Atim.Unix()).UTC(), true
}
