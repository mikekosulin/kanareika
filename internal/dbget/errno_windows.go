//go:build windows

package dbget

import (
	"errors"
	"syscall"
)

// Winsock's codes (WSAECONNREFUSED and the rest): syscall's ECONNREFUSED is not what a refused dial returns there
const (
	wsaENETUNREACH  = syscall.Errno(10051)
	wsaECONNRESET   = syscall.Errno(10054)
	wsaECONNREFUSED = syscall.Errno(10061)
	wsaEHOSTUNREACH = syscall.Errno(10065)
)

func refused(err error) bool {
	return errors.Is(err, wsaECONNREFUSED) || errors.Is(err, syscall.ECONNREFUSED)
}
func reset(err error) bool {
	return errors.Is(err, wsaECONNRESET) || errors.Is(err, syscall.ECONNRESET)
}
func unreachable(err error) bool {
	return errors.Is(err, wsaENETUNREACH) || errors.Is(err, wsaEHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)
}
