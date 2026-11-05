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
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// setupUser is who the daemon serves: the person running setup, also when
// they ran it under sudo.
func setupUser() (uid, gid int, err error) {
	uid, gid = os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, _ = strconv.Atoi(os.Getenv("SUDO_UID"))
		gid, _ = strconv.Atoi(os.Getenv("SUDO_GID"))
	}
	if uid <= 0 {
		return 0, 0, fmt.Errorf("setup has to know whose services to serve: run it as yourself, not as root")
	}
	return uid, gid, nil
}

// setupHome is the names folder of the person running setup, also when they
// ran it under sudo: root's HOME is not theirs, and a daemon pointed at
// /root/.doze answers the zone from an empty registry.
func setupHome() string {
	if h := os.Getenv(EnvHome); h != "" {
		return h
	}
	if os.Getuid() == 0 {
		if uid := os.Getenv("SUDO_UID"); uid != "" {
			if u, err := user.LookupId(uid); err == nil && u.HomeDir != "" {
				return filepath.Join(u.HomeDir, "."+Suffix)
			}
		}
	}
	return Home()
}

// netdOwner is how the daemon signs the registry while it serves: what a
// peer logs when it stands by, and what doctor names as the resolver.
const netdOwner = "doze-netd"

// netdVersion goes into the daemon's job (the launchd plist, the systemd
// unit), so a build whose daemon differs from the one installed sees a job
// that is not its own and installs again, and check reports the older
// daemon until it does. Raise it whenever the daemon's behaviour changes.
//
//	1  translates packets (macOS)
//	2  also answers the zone when no doze program does; on Linux, the
//	   daemon exists from this version and does only that
const netdVersion = "2"

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// jobOutdated reports that the job at path starts a daemon older than this
// build's: it is there, and does not carry stamp, the platform's spelling
// of this build's netdVersion. The daemon is the copy setup made, so the
// job is the version that runs.
func jobOutdated(path, stamp string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return !strings.Contains(string(raw), stamp)
}

// serveZone holds the resolver from the registry at path, on the zone's
// address, for as long as ctx lasts, standing by while a doze program has
// it. The address is ResolverAddr, read from the environment like every
// peer's: a daemon started by hand for a private zone has to be given that
// zone's DOZE_ZONE_RESOLVER, or it serves the real one from the wrong file.
func serveZone(ctx context.Context, path string, logf func(string, ...any)) *Server {
	return Serve(ctx, Open(filepath.Dir(path), netdOwner), logf)
}
