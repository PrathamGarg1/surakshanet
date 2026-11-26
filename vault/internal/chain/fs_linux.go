//go:build linux

package chain

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	fsIOCGetFlags = 0x80086601
	fsIOCSetFlags = 0x40086602
	fsAppendFL    = 0x00000020
)

// TryEnableAppendOnly attempts to set the Linux kernel FS_APPEND_FL attribute
// (equivalent to `chattr +a`) on the vault log file. This requires root with
// CAP_LINUX_IMMUTABLE and a supporting filesystem (ext4/xfs/btrfs).
// Returns true if kernel append-only protection is active, false otherwise.
func TryEnableAppendOnly(f *os.File) bool {
	var flags int
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(fsIOCGetFlags), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return false
	}
	if flags&fsAppendFL != 0 {
		return true
	}
	flags |= fsAppendFL
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(fsIOCSetFlags), uintptr(unsafe.Pointer(&flags)))
	return errno == 0
}
