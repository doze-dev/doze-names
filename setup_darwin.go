package names

// macOS setup: alias the loopback pool onto lo0, and route the zone to the
// resolver over unicast DNS.
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
	"strings"
	"time"
)

const (
	launchdLabel = "dev.doze.loopback"
	launchdPath  = "/Library/LaunchDaemons/dev.doze.loopback.plist"
	resolverFile = "/etc/resolver/" + Suffix
)

// launchdPlist aliases the whole pool at boot and, via RunAtLoad, right now.
func launchdPlist() string {
	script := fmt.Sprintf("for i in $(seq %d %d); do /sbin/ifconfig lo0 alias 127.0.0.$i up; done",
		apexBase, dynamicEnd)
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + launchdLabel + `</string>
  <key>RunAtLoad</key><true/>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>` + script + `</string>
  </array>
</dict>
</plist>
`
}

// aliasesAvailable reports whether the pool is actually usable, by binding one
// of it. Checking ifconfig output would be checking what was configured; this
// checks what works.
func aliasesAvailable() bool {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.%d:0", apexBase))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
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

	detail := "127.0.0." + fmt.Sprint(apexBase) + "-" + fmt.Sprint(dynamicEnd) + " aliased on lo0"
	if !aliasesAvailable() {
		detail = "not aliased — services cannot hold canonical ports"
	}
	st.Steps = append(st.Steps, Step{Name: "loopback pool", Done: aliasesAvailable(), Detail: detail})

	detail = resolverFile + " → " + ResolverAddr()
	if !resolverInstalled() {
		detail = resolverFile + " missing — ." + Suffix + " will not resolve"
	}
	st.Steps = append(st.Steps, Step{Name: "resolver route", Done: resolverInstalled(), Detail: detail})

	return st
}

func install(o Options) error {
	if check().OK() {
		if cur, err := os.ReadFile(launchdPath); err == nil && string(cur) == launchdPlist() {
			fmt.Fprintln(o.out(), "✓ already set up — nothing to do")
			return nil
		}
	}

	_, port, _ := net.SplitHostPort(ResolverAddr())
	// Reload rather than a bare load, so re-running after the pool changes
	// re-fires RunAtLoad and aliases the new addresses in this session rather
	// than only at the next boot.
	script := fmt.Sprintf(`set -e
cat > %s <<'PLIST'
%sPLIST
launchctl bootout system %s 2>/dev/null || launchctl unload %s 2>/dev/null || true
launchctl load -w %s 2>/dev/null || launchctl bootstrap system %s 2>/dev/null || true
mkdir -p /etc/resolver
printf 'nameserver 127.0.0.1\nport %s\n' > %s`,
		launchdPath, launchdPlist(), launchdPath, launchdPath,
		launchdPath, launchdPath, port, resolverFile)

	if err := runPrivileged(o, "alias the loopback pool onto lo0 and route ."+Suffix+" to the resolver", script); err != nil {
		return err
	}
	if o.Print {
		return nil
	}

	// launchd applies RunAtLoad asynchronously, so the aliases can land a beat
	// after launchctl returns.
	for i := 0; i < 20 && !aliasesAvailable(); i++ {
		time.Sleep(150 * time.Millisecond)
	}
	if !aliasesAvailable() {
		return fmt.Errorf("setup ran but 127.0.0.%d is still not bindable — check `sudo ifconfig lo0`, then re-run with --check", apexBase)
	}
	fmt.Fprintf(o.out(), "✓ loopback pool aliased and *.%s routed to the resolver\n", Suffix)
	return nil
}

func uninstall(o Options) error {
	script := strings.Join([]string{
		"launchctl bootout system " + launchdPath + " 2>/dev/null || launchctl unload " + launchdPath + " 2>/dev/null || true",
		"rm -f " + launchdPath,
		"rm -f " + resolverFile,
	}, "\n")
	if err := runPrivileged(o, "remove the loopback job and the resolver route", script); err != nil {
		return err
	}
	if !o.Print {
		fmt.Fprintln(o.out(), "✓ removed — the aliases themselves clear at the next reboot")
	}
	return nil
}
