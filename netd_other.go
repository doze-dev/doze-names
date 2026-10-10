//go:build !darwin

package names

import "errors"

// Only macOS needs the daemon: everywhere else a name's address is local and
// the service binds it.
func runNetd([]string) error {
	return errors.New("netd: this system binds addresses directly and has no network daemon")
}
