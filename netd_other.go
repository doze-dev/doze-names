//go:build !darwin && !linux

package names

import "errors"

// Only macOS and Linux have the daemon: elsewhere a name's address is local,
// the service binds it, and nothing holds the zone when no program runs.
func runNetd([]string) error {
	return errors.New("netd: this system has no network daemon")
}
