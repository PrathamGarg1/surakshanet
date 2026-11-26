//go:build linux

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// PeerCredentials extracts the kernel-verified UID and PID of the client
// connected to a Unix domain socket via SO_PEERCRED.
func PeerCredentials(conn net.Conn) (uid int, pid int) {
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, -1
	}
	raw, err := uconn.SyscallConn()
	if err != nil {
		return -1, -1
	}
	uid, pid = -1, -1
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err == nil && cred != nil {
			uid = int(cred.Uid)
			pid = int(cred.Pid)
		}
	})
	return uid, pid
}
