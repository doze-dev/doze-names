//go:build !darwin

package names

// Only a Mac has a daemon to ask about.
func servesHome() bool { return false }
