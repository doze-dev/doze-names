package names

// macOS setup: install the network daemon, and route the zone to the resolver
// over unicast DNS.
//
// The daemon is what gives every service an address of its own (pool.go has
// the reason it is a daemon and not a pool of loopback aliases).
//
// The unicast route is not optional, and the reason is easy to lose: macOS
// getaddrinfo DROPS loopback addresses other than 127.0.0.1 when they are
// learned via mDNS, as a security guard. So per-service addresses cannot be
// published over Bonjour — they have to come from a real DNS server, which is
// what /etc/resolver/doze points at. Anyone reaching for mDNS to avoid the
// setup step will find names that resolve everywhere except where it matters.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	launchdLabel = "dev.doze.netd"
	launchdPath  = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	helperPath   = "/Library/PrivilegedHelperTools/" + launchdLabel
	helperLog    = "/var/log/doze-netd.log"
	resolverFile = "/etc/resolver/" + Suffix

	// The job that aliased a pool of loopback addresses, before the daemon.
	oldLaunchdPath = "/Library/LaunchDaemons/dev.doze.loopback.plist"

	// netdVersion goes into the job, so a build whose daemon differs from the
	// one installed sees a job that is not its own and installs again. Raise
	// it whenever the daemon's behaviour changes.
	netdVersion = "1"
)

// launchdPlist starts the daemon at boot and keeps it running. It is told the
// registry to translate from and the user to run as once the interface is up.
func launchdPlist(registry string, uid, gid int) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + launchdLabel + `</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardErrorPath</key><string>` + helperLog + `</string>
  <key>EnvironmentVariables</key>
  <dict><key>DOZE_NETD_VERSION</key><string>` + netdVersion + `</string></dict>
  <key>ProgramArguments</key>
  <array>
    <string>` + helperPath + `</string>
    <string>` + helperArg + `</string>
    <string>` + xmlEscape(registry) + `</string>
    <string>` + strconv.Itoa(uid) + `</string>
    <string>` + strconv.Itoa(gid) + `</string>
  </array>
</dict>
</plist>
`
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

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

func resolverInstalled() bool {
	raw, err := os.ReadFile(resolverFile)
	if err != nil {
		return false
	}
	s := string(raw)
	_, port, _ := net.SplitHostPort(ResolverAddr())
	return strings.Contains(s, "127.0.0.1") && strings.Contains(s, port)
}

func check() Status {
	st := Status{Platform: "darwin"}

	up := gatewayUp()
	detail := zone.cidr() + " served by the doze network daemon"
	if !up {
		detail = "the doze network daemon is not running — services cannot hold canonical ports"
		if _, err := os.Stat(launchdPath); err == nil {
			detail += " (see " + helperLog + ")"
		}
	}
	st.Steps = append(st.Steps, Step{Name: "network", Done: up, Detail: detail})

	detail = resolverFile + " → " + ResolverAddr()
	if !resolverInstalled() {
		detail = resolverFile + " missing — ." + Suffix + " will not resolve"
	}
	st.Steps = append(st.Steps, Step{Name: "resolver route", Done: resolverInstalled(), Detail: detail})

	return st
}

func install(o Options) error {
	uid, gid, err := setupUser()
	if err != nil {
		return err
	}
	plist := launchdPlist(filepath.Join(Home(), FileName), uid, gid)
	if check().OK() {
		if cur, err := os.ReadFile(launchdPath); err == nil && string(cur) == plist {
			fmt.Fprintln(o.out(), "✓ already set up — nothing to do")
			return nil
		}
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("setup: cannot find this program to install as the daemon: %w", err)
	}

	_, port, _ := net.SplitHostPort(ResolverAddr())
	// The daemon is a copy of this program, so it does not vanish when the
	// program is upgraded or moved. bootout before bootstrap, so re-running
	// setup restarts a daemon that is already there on the new copy.
	script := fmt.Sprintf(`set -e
launchctl bootout system %[1]s 2>/dev/null || true
launchctl bootout system %[2]s 2>/dev/null || true
rm -f %[2]s
mkdir -p %[3]s
cp -f %[4]s %[5]s
chown root:wheel %[5]s
chmod 755 %[5]s
cat > %[1]s <<'PLIST'
%[6]sPLIST
launchctl bootstrap system %[1]s
mkdir -p /etc/resolver
printf 'nameserver 127.0.0.1\nport %[7]s\n' > %[8]s`,
		launchdPath, oldLaunchdPath, shellQuote(filepath.Dir(helperPath)), shellQuote(self), helperPath,
		plist, port, resolverFile)

	if err := runPrivileged(o, "install the doze network daemon and route ."+Suffix+" to the resolver", script); err != nil {
		return err
	}
	if o.Print {
		return nil
	}

	// launchd starts the daemon asynchronously, so the interface can appear a
	// beat after launchctl returns.
	for i := 0; i < 40 && !gatewayUp(); i++ {
		time.Sleep(150 * time.Millisecond)
	}
	if !gatewayUp() {
		return fmt.Errorf("setup ran but the network daemon did not come up — see %s, then re-run with --check", helperLog)
	}
	fmt.Fprintf(o.out(), "✓ network daemon running and *.%s routed to the resolver\n", Suffix)
	return nil
}

func uninstall(o Options) error {
	script := strings.Join([]string{
		"launchctl bootout system " + launchdPath + " 2>/dev/null || true",
		"launchctl bootout system " + oldLaunchdPath + " 2>/dev/null || true",
		"rm -f " + launchdPath + " " + oldLaunchdPath + " " + helperPath,
		"rm -f " + resolverFile,
	}, "\n")
	if err := runPrivileged(o, "remove the network daemon and the resolver route", script); err != nil {
		return err
	}
	if !o.Print {
		fmt.Fprintln(o.out(), "✓ removed")
	}
	return nil
}
