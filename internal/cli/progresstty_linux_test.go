//go:build linux

package cli

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// openPTY: the terminal end of a new pseudo-terminal of the test's own (never the one the tests run in); the
// test is skipped where the system has none.
func openPTY(t *testing.T) *os.File {
	t.Helper()
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no pseudo-terminals:", err)
	}
	t.Cleanup(func() { ptm.Close() })
	fd := int(ptm.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil { // unlockpt
		t.Skip("unlockpt:", err)
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN) // ptsname
	if err != nil {
		t.Skip("ptsname:", err)
	}
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no /dev/pts:", err)
	}
	t.Cleanup(func() { pts.Close() })
	return pts
}

// TestProgressTTYWidth: on a terminal the progress is drawn as wide as it is; one too narrow for the bars, or that
// does not say its size, counts as 80 columns.
func TestProgressTTYWidth(t *testing.T) {
	pts := openPTY(t)
	for _, c := range []struct {
		cols uint16
		want int
	}{{120, 120}, {30, 80}, {0, 80}} {
		must(t, unix.IoctlSetWinsize(int(pts.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: c.cols}))
		if w, tty := progressTTY(pts); !tty || w != c.want {
			t.Errorf("%d columns: %d %v, want %d", c.cols, w, tty, c.want)
		}
	}
}
