//go:build windows

package report

import (
	"errors"
	"math"
	"os"

	"golang.org/x/sys/windows"
)

// lockFile: an exclusive LockFileEx on the whole file; busy when wait is false and another process holds it.
func lockFile(f *os.File, wait bool) (busy bool, err error) {
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if !wait {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	err = windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, math.MaxUint32, math.MaxUint32, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return true, nil
	}
	return false, err
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, math.MaxUint32, math.MaxUint32, &windows.Overlapped{})
}
