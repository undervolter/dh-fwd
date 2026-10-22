//go:build windows

package core

import (
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// udpControl disables SIO_UDP_CONNRESET: without it, an ICMP port-unreachable
// from any past send poisons the next ReadFromUDP with WSAECONNRESET,
// killing the socket early. Linux never reports this on unconnected sockets.
func udpControl(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		var off uint32
		var ret uint32
		sockErr = windows.WSAIoctl(windows.Handle(fd), windows.SIO_UDP_CONNRESET,
			(*byte)(unsafe.Pointer(&off)), uint32(unsafe.Sizeof(off)),
			nil, 0, &ret, nil, 0)
	})
	if err != nil {
		return err
	}
	return sockErr
}

func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	return err == syscall.ECONNRESET ||
		err == windows.WSAECONNRESET ||
		strings.Contains(err.Error(), "connection reset")
}

func setSocketDF(conn *net.UDPConn) {
	if sc, err := conn.SyscallConn(); err == nil {
		_ = sc.Control(func(fd uintptr) {
			_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 14 /* IP_DONTFRAGMENT */, 1)
		})
	}
}
