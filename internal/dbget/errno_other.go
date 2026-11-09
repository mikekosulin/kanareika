//go:build !windows

package dbget

import (
	"errors"
	"syscall"
)

// the socket errors a reason names, as this system reports them
func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
func reset(err error) bool   { return errors.Is(err, syscall.ECONNRESET) }
func unreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)
}
