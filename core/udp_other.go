//go:build !windows

package core

import (
	"errors"
	"syscall"
)

func udpControl(network, address string, c syscall.RawConn) error {
	return nil
}

func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}
