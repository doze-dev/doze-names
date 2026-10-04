//go:build !windows

package names

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on f, blocking until it has it, and
// returns the function that releases it.
func lockFile(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
}

// alive reports whether a process exists. Signal 0 checks for existence
// without delivering anything; EPERM means it exists and belongs to someone
// else, which still counts as alive.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
