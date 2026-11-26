//go:build !linux

package ipc

import "net"

func PeerCredentials(_ net.Conn) (uid int, pid int) {
	return -1, -1
}
