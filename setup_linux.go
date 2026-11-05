package names

// Linux setup. There is no /etc/resolver equivalent, so this is four problems
// wearing one coat.
//
// Which DNS manager owns the machine is decided by the marker comment in
// /etc/resolv.conf rather than by probing what is running — the same test
// Tailscale settled on after doing this the hard way. A running systemd-resolved
// that nothing points at is not the machine's resolver, and probing for the
// process says it is.
//
// The important limit: PLAIN /etc/resolv.conf CANNOT DO SPLIT DNS. There is no
// per-domain routing in that format at all. The only way to serve one zone from
// there is to become the machine's resolver for everything, which is what
// Tailscale does and what a local development tool has no business doing. On
// those machines apex names come from /etc/hosts and per-stack names simply do
// not resolve — stated plainly rather than worked around.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	sysctlPath  = "/etc/sysctl.d/60-doze.conf"
	dnsmasqDrop = "/etc/dnsmasq.d/doze.conf"
	resolvConf  = "/etc/resolv.conf"
	unitPath    = "/etc/systemd/system/doze-names.service"
	unitName    = "doze-names.service"

	// The daemon that answers the zone when no doze program does (netd.go):
	// a copy of the program that ran setup, and its unit.
	netdPath     = "/usr/local/libexec/doze-netd"
	netdUnitPath = "/etc/systemd/system/doze-netd.service"
	netdUnitName = "doze-netd.service"
	netdStamp    = "Environment=DOZE_NETD_VERSION=" + netdVersion
)

// netdUnit runs the daemon as the person who ran setup, after the zone unit
// has made the interface the resolver binds, and keeps it running.
func netdUnit(registry string, uid, gid int) string {
	return `[Unit]
Description=doze: answers the ` + Suffix + ` zone when no doze program does
After=` + unitName + `
Wants=` + unitName + `

[Service]
User=` + fmt.Sprint(uid) + `
Group=` + fmt.Sprint(gid) + `
` + netdStamp + `
ExecStart=` + netdPath + ` ` + helperArg + ` ` + registry + `
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`
}

// netdOutdated reports that the unit starts a daemon older than this build's
// (netd.go).
func netdOutdated() bool { return jobOutdated(netdUnitPath, netdStamp) }

// netdActive reports whether systemd has the daemon running.
func netdActive() bool {
	out, err := exec.Command("systemctl", "is-active", netdUnitName).Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// netdStep is the daemon's line in check: in place only when the unit is
// this build's and running.
func netdStep() Step {
	st := Step{Name: "network daemon", Detail: "answers the zone when no doze program runs, so a routed domain is never dark"}
	switch {
	case !fileExists(netdUnitPath):
		st.Detail = "not installed — a routed domain is unreachable while no stack runs"
	case netdOutdated():
		st.Detail = "from an older setup — run setup again (one sudo), so a routed domain is answered when no stack runs"
	case netdServes() != "" && netdServes() != filepath.Join(setupHome(), FileName):
		// Set up under a sudo that swapped HOME for root's: the daemon answers
		// from a registry nobody writes.
		st.Detail = "answers from " + netdServes() + ", not your registry — run setup again (one sudo)"
	case !netdActive():
		st.Detail = "installed but not running (systemctl status " + netdUnitName + ")"
	default:
		st.Done = true
	}
	return st
}

// zoneUnit creates the resolver's interface and, on a systemd-resolved machine,
// points resolved at it.
//
// It is a unit rather than a config file for two reasons. The interface has to
// exist at boot, before anything asks for a name. And resolved will only take a
// per-LINK server — a global DNS= in resolved.conf.d is parsed and then
// silently dropped when it names a loopback address, which is what the first
// implementation did and why it never worked. resolvectl writes runtime state
// that does not survive a reboot, so the unit re-applies it every time.
//
// Every ExecStart is prefixed "-": re-running setup must not fail because the
// link already exists.
func zoneUnit(routeResolved bool) string {
	u := `[Unit]
Description=doze: the ` + Suffix + ` name zone
After=systemd-resolved.service
Wants=systemd-resolved.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-/sbin/ip link add ` + resolverIface + ` type dummy
ExecStart=-/sbin/ip addr add ` + resolverIP + `/32 dev ` + resolverIface + `
ExecStart=-/sbin/ip link set ` + resolverIface + ` up
`
	if routeResolved {
		u += `ExecStart=-/usr/bin/resolvectl dns ` + resolverIface + ` ` + resolverIP + `:` + resolverPort + `
ExecStart=-/usr/bin/resolvectl domain ` + resolverIface + ` ~` + Suffix + `
`
	}
	u += `ExecStop=-/sbin/ip link del ` + resolverIface + `

[Install]
WantedBy=multi-user.target
`
	return u
}

// unprivilegedPortStart is what the sysctl must allow: 80, for the shared front
// door. The resolver no longer needs it — it sits on a high port, because 53 is
// held on the wildcard by whatever already serves DNS.
const unprivilegedPortStart = 80

// dnsmasqPresent reports whether dnsmasq is RUNNING, not merely installed.
//
// Installed-but-idle is common — it arrives as a dependency of other packages —
// and writing a drop-in for a daemon nobody is using produces a config that
// does nothing while the setup report claims the route is in place. That is a
// false success, which is worse than an honest "not available".
//
// This still does not prove dnsmasq is the machine's resolver, only that it is
// up and reading its conf.d. Proving the rest means comparing resolv.conf's
// nameserver against what dnsmasq is bound to, which is a heuristic of its own;
// requiring it to be running removes the common false positive cheaply.
func dnsmasqPresent() bool {
	if _, err := os.Stat("/etc/dnsmasq.d"); err != nil {
		return false
	}
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		return false
	}
	out, err := exec.Command("systemctl", "is-active", "dnsmasq").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		return true
	}
	// No systemd, or a dnsmasq started some other way: fall back to asking
	// whether a process is there at all.
	return exec.Command("pgrep", "-x", "dnsmasq").Run() == nil
}

// detect reads the marker comment rather than probing processes.
func detect() manager {
	raw, err := os.ReadFile(resolvConf)
	if err != nil {
		return mgrUnknown
	}
	return detectFrom(string(raw))
}

func sysctlInstalled() bool {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil {
		return false
	}
	var cur int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &cur); err != nil {
		return false
	}
	return cur <= unprivilegedPortStart
}

// resolverRouteInstalled mirrors what install writes, and has to keep
// mirroring it: install chooses the drop-in by "is this systemd-resolved, else
// is dnsmasq running", so checking by manager alone reported a route missing on
// a machine where it had just been written — a plain resolv.conf with dnsmasq
// running is exactly that case, and Colima is exactly that machine.
// resolverRouteInstalled mirrors what install writes, and has to keep
// mirroring it. Both paths need the interface unit; systemd-resolved needs
// nothing else, dnsmasq needs its drop-in as well.
func resolverRouteInstalled(m manager) bool {
	raw, err := os.ReadFile(unitPath)
	if err != nil || !strings.Contains(string(raw), resolverIP) {
		return false
	}
	if m == mgrResolved {
		return strings.Contains(string(raw), "resolvectl")
	}
	drop, err := os.ReadFile(dnsmasqDrop)
	return err == nil && strings.Contains(string(drop), resolverIP)
}

func check() Status {
	m := detect()
	st := Status{Platform: "linux (" + m.String() + ")"}

	detail := fmt.Sprintf("ports ≥ %d bindable unprivileged", unprivilegedPortStart)
	if !sysctlInstalled() {
		detail = "not applied — services cannot bind :80 (the resolver is unaffected: it uses " + resolverPort + ")"
	}
	st.Steps = append(st.Steps, Step{Name: "unprivileged ports", Done: sysctlInstalled(), Detail: detail})

	detail = "apex names in " + hostsPath
	if !hostsBlockInstalled() {
		detail = "missing — aws." + Suffix + " will not resolve"
	}
	st.Steps = append(st.Steps, Step{Name: "hosts block", Done: hostsBlockInstalled(), Detail: detail})

	// The resolver route is reported as a step only where it is achievable.
	// Listing it as failed on a machine that structurally cannot do split DNS
	// would be reporting the OS as broken.
	switch {
	case canRouteDomain(m, dnsmasqPresent()):
		detail = "per-stack names routed to " + ResolverAddr()
		if !resolverRouteInstalled(m) {
			detail = "not configured — only apex names will resolve"
		}
		st.Steps = append(st.Steps, Step{Name: "resolver route", Done: resolverRouteInstalled(m), Detail: detail})
		st.Steps = append(st.Steps, netdStep())
	default:
		st.Steps = append(st.Steps, Step{
			Name: "resolver route", Done: true,
			Detail: "n/a on " + m.String() + " — apex names via " + hostsPath + ", per-stack names unavailable",
		})
	}
	return st
}

func install(o Options) error {
	m := detect()

	hosts, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", hostsPath, err)
	}
	wantHosts := replaceHostsBlock(string(hosts), apexHostsBlock())

	var b strings.Builder
	b.WriteString("set -e\n")

	// mkdir first, and the whole write allowed to fail.
	//
	// debian:stable-slim has no /etc/sysctl.d at all, so `printf ... > file`
	// died with "Directory nonexistent" and `set -e` took the install with it:
	// doze-aws exited fatally and the container could not start. alpine ships
	// the directory, which is why this only ever showed up on one of the two
	// images the docs claimed to cover.
	//
	// `|| true` for the same reason the apply below has it — this key is
	// optional, and nothing downstream depends on the file existing.
	fmt.Fprintf(&b, "mkdir -p %s && printf %s > %s || true\n",
		filepath.Dir(sysctlPath),
		shellQuote(fmt.Sprintf("# doze: lets the shared front door bind :80 unprivileged\nnet.ipv4.ip_unprivileged_port_start=%d\n", unprivilegedPortStart)),
		sysctlPath)
	// Our own file, and allowed to fail.
	//
	// `sysctl --system` was the obvious spelling and it is the wrong one: it
	// does not apply one key, it REAPPLIES EVERY sysctl.d file on the machine.
	// Inside a container most of /proc/sys is read-only, so it fails on keys
	// that have nothing to do with doze — kernel.sysrq, kernel.core_uses_pid,
	// net.ipv4.conf.* — and `set -e` then aborts the script before the hosts
	// block is written. The whole install failed for the sake of a setting
	// nobody asked about.
	//
	// `|| true` because this key is the one optional step here. It exists so an
	// UNPRIVILEGED process can bind :80; a container runs as root and can bind
	// it anyway, and where it genuinely cannot be set, everything downstream
	// already copes — ingress logs "names will need their port" at bind time,
	// Status reports the step as not done, and names still resolve and still
	// work with their port. Failing the install over it costs the hosts block,
	// which is the part that matters.
	fmt.Fprintf(&b, "sysctl -q -p %s || true\n", sysctlPath)

	// Written whole rather than appended, so re-running cannot grow the file.
	fmt.Fprintf(&b, "printf %s > %s\n", shellQuote(wantHosts), hostsPath)

	// The resolver's interface, on both paths: it is where the resolver binds,
	// not only what resolved is pointed at.
	if canRouteDomain(m, dnsmasqPresent()) {
		fmt.Fprintf(&b, "printf %s > %s\n", shellQuote(zoneUnit(m == mgrResolved)), unitPath)
		fmt.Fprintf(&b, "systemctl daemon-reload && systemctl enable --now %s\n", unitName)
		fmt.Fprintf(&b, "systemctl restart %s\n", unitName)
		if m != mgrResolved {
			fmt.Fprintf(&b, "mkdir -p %s\n", "/etc/dnsmasq.d")
			fmt.Fprintf(&b, "printf %s > %s\n",
				shellQuote(fmt.Sprintf("server=/%s/%s#%s\n", Suffix, resolverIP, resolverPort)), dnsmasqDrop)
			b.WriteString("systemctl restart dnsmasq 2>/dev/null || true\n")
		}
		// The daemon that answers the zone from that interface when no doze
		// program does: a copy of this program, so it does not vanish when
		// the program is upgraded or moved, run as the person who ran setup.
		// Restarted, so re-running setup puts the new copy to work.
		uid, gid, err := setupUser()
		if err != nil {
			return err
		}
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("setup: cannot find this program to install as the daemon: %w", err)
		}
		fmt.Fprintf(&b, "mkdir -p %s && cp -f %s %s && chown root:root %s && chmod 755 %s\n",
			shellQuote(filepath.Dir(netdPath)), shellQuote(self), netdPath, netdPath, netdPath)
		fmt.Fprintf(&b, "printf %s > %s\n", shellQuote(netdUnit(filepath.Join(setupHome(), FileName), uid, gid)), netdUnitPath)
		fmt.Fprintf(&b, "systemctl daemon-reload && systemctl enable --now %s && systemctl restart %s\n", netdUnitName, netdUnitName)
	}

	what := "apply the sysctl, write the " + hostsPath + " block"
	if canRouteDomain(m, dnsmasqPresent()) {
		what += ", route ." + Suffix + " to the resolver, and install the daemon that answers it when no stack runs"
	}
	if err := runPrivileged(o, what, b.String()); err != nil {
		return err
	}
	if o.Print {
		return nil
	}

	fmt.Fprint(o.out(), check().String())
	if !canRouteDomain(m, dnsmasqPresent()) {
		fmt.Fprintf(o.out(),
			"\nnote: %s cannot route a single domain, so per-stack names (<service>.<stack>.%s)\n"+
				"will not resolve here. Apex names work via %s. Installing systemd-resolved or\n"+
				"dnsmasq would enable the rest; doze will not take over your machine's DNS to do it.\n",
			m, Suffix, hostsPath)
	}
	return nil
}

func uninstall(o Options) error {
	hosts, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", hostsPath, err)
	}
	stripped := replaceHostsBlock(string(hosts), "")

	var b strings.Builder
	b.WriteString("set -e\n")
	fmt.Fprintf(&b, "systemctl disable --now %s 2>/dev/null || true\n", netdUnitName)
	fmt.Fprintf(&b, "systemctl disable --now %s 2>/dev/null || true\n", unitName)
	fmt.Fprintf(&b, "ip link del %s 2>/dev/null || true\n", resolverIface)
	fmt.Fprintf(&b, "rm -f %s %s %s %s %s\n", sysctlPath, unitPath, dnsmasqDrop, netdUnitPath, netdPath)
	b.WriteString("systemctl daemon-reload 2>/dev/null || true\n")
	fmt.Fprintf(&b, "printf %s > %s\n", shellQuote(stripped), hostsPath)
	b.WriteString("sysctl -q --system 2>/dev/null || true\n")
	// Restart BOTH: uninstall removes whichever drop-in was written, and the
	// daemon keeps serving the old config until it re-reads it. Leaving dnsmasq
	// pointing .doze at a resolver that is gone is a worse state than never
	// having configured it.
	b.WriteString("systemctl restart systemd-resolved 2>/dev/null || true\n")
	b.WriteString("systemctl restart dnsmasq 2>/dev/null || true\n")
	// The domains' routes drop-in and the authority's trust go too.
	fmt.Fprintf(&b, "rm -rf %s\n", shellQuote(filepath.Dir(routesDropIn)))
	for _, line := range cleanupScript(Home()) {
		b.WriteString(line + "\n")
	}

	if err := runPrivileged(o, "remove the sysctl, the hosts block, the resolver route, the domains' routes and the certificate authority", b.String()); err != nil {
		return err
	}
	if !o.Print {
		cleanupAfter(Home())
		fmt.Fprintln(o.out(), "✓ removed")
	}
	return nil
}

// netdServes is the registry the installed unit points the daemon at: the
// last word of its ExecStart line, or "" when there is no unit.
func netdServes() string {
	b, err := os.ReadFile(netdUnitPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			f := strings.Fields(line)
			if len(f) > 0 {
				return f[len(f)-1]
			}
		}
	}
	return ""
}
