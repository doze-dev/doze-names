//go:build windows

package names

import (
	"os"
	"syscall"
	"unsafe"
)

// The registry's lock and liveness check, for Windows. LockFileEx is called through
// kernel32 directly rather than golang.org/x/sys/windows, which would be this
// module's only dependency.
var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	procLockFile = kernel32.NewProc("LockFileEx")
	procUnlock   = kernel32.NewProc("UnlockFileEx")
)

const lockfileExclusiveLock = 0x2

// lockFile takes an exclusive lock on f, blocking until it has it, and returns the
// function that releases it. One byte at offset 0 is locked: the file is a sidecar
// used only for this, so what is locked does not matter, only that it is the same
// byte for every process.
func lockFile(f *os.File) (func(), error) {
	var ol syscall.Overlapped
	r, _, err := procLockFile.Call(f.Fd(), lockfileExclusiveLock, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return nil, err
	}
	return func() {
		var ol syscall.Overlapped
		procUnlock.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol))) //nolint:errcheck
	}, nil
}

// alive reports whether a process exists. On Windows os.FindProcess opens a handle
// to it and fails if there is none.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
