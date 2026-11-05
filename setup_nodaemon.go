//go:build !darwin

package names

// Only a Mac's daemon serves a home's addresses; the Linux one answers the
// zone and is asked about through systemd (setup_linux.go).
func servesHome() bool { return false }
