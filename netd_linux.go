package names

// The Linux network daemon. A name's address is local here and the service
// binds it, so there is nothing to translate; the daemon exists for the
// zone's resolver alone (netd.go). systemd starts it at boot as the user
// who ran setup, so it opens the resolver's socket on the interface the
// zone unit made, and with no doze program running a routed domain is
// still answered: forwarded to the machine's own DNS, the real host.

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// runNetd is the daemon. Its one argument is the registry file to answer
// from. It is started as the user already, by the unit, and never as root:
// it has nothing to do that needs it, and the registry is the user's.
func runNetd(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: " + helperArg + " <registry>")
	}
	if os.Getuid() == 0 {
		return errors.New("netd: runs as the user whose zone it answers, never as root (the unit says who)")
	}
	registry := args[0]
	fmt.Fprintf(os.Stderr, "netd: answering the zone from %s on %s as uid %d\n", registry, ResolverAddr(), os.Getuid())
	// The daemon only ever stops by being killed, so its context never ends.
	serveZone(context.Background(), registry, func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) })
	select {}
}
