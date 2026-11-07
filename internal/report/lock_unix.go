//go:build !windows

package report

import (
	"errors"
	"os"
	"syscall"
)

// lockFile: an exclusive flock; busy when wait is false and another process holds it.
func lockFile(f *os.File, wait bool) (busy bool, err error) {
	how := syscall.LOCK_EX
	if !wait {
		how |= syscall.LOCK_NB
	}
	for {
		err = syscall.Flock(int(f.Fd()), how)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
