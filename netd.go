package names

// The network daemon's second job, on the platform that has one: holding the
// zone's resolver whenever no doze program does.
//
// The resolver is first-come among the doze programs on the machine, and
// that was enough while every name was a .doze name: with no program
// running, nothing is registered, and a lookup that fails fast is the right
// answer. A routed domain changed that. /etc/resolver/dev.acme.com sends the
// name here for as long as the route exists, and with doze fully down the
// route pointed at a port nobody listened on, so the real dev.acme.com was
// unreachable from this machine until a stack came up. The daemon runs from
// boot, so it is the peer that is always there: it joins the same first-come
// loop as every other program, takes the socket when none of them holds it,
// answers the zone from the registry as they would, and forwards a routed
// domain nobody declares to the machine's own upstreams. A program that
// starts later stands by, exactly as it would behind any peer, and the names
// resolve the same either way.

import (
	"context"
	"path/filepath"
)

// netdOwner is how the daemon signs the registry while it serves: what a
// peer logs when it stands by, and what doctor names as the resolver.
const netdOwner = "doze-netd"

// serveZone holds the resolver from the registry at path, on the zone's
// address, for as long as ctx lasts, standing by while a doze program has
// it. The address is ResolverAddr, read from the environment like every
// peer's: a daemon started by hand for a private zone has to be given that
// zone's DOZE_ZONE_RESOLVER, or it serves the real one from the wrong file.
func serveZone(ctx context.Context, path string, logf func(string, ...any)) *Server {
	return Serve(ctx, Open(filepath.Dir(path), netdOwner), logf)
}
