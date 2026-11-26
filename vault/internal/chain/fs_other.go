//go:build !linux

package chain

import "os"

// TryEnableAppendOnly is a no-op on non-Linux platforms; Windows uses NTFS ACLs
// configured by deploy/windows/install.ps1 and macOS uses chflags sappend.
func TryEnableAppendOnly(_ *os.File) bool {
	return false
}
