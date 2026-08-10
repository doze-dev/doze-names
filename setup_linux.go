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
	"strings"
)

const (
	sysctlPath   = "/etc/sysctl.d/60-doze.conf"
	resolvedDrop = "/etc/systemd/resolved.conf.d/doze.conf"
	dnsmasqDrop  = "/etc/dnsmasq.d/doze.conf"
	resolvConf   = "/etc/resolv.conf"
)

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
func resolverRouteInstalled(m manager) bool {
	drop := dnsmasqDrop
	if m == mgrResolved {
		drop = resolvedDrop
	}
	raw, err := os.ReadFile(drop)
	return err == nil && strings.Contains(string(raw), resolverIP)
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

	fmt.Fprintf(&b, "printf %s > %s\n",
		shellQuote(fmt.Sprintf("# doze: lets the shared front door bind :80 unprivileged\nnet.ipv4.ip_unprivileged_port_start=%d\n", unprivilegedPortStart)),
		sysctlPath)
	b.WriteString("sysctl -q --system\n")

	// Written whole rather than appended, so re-running cannot grow the file.
	fmt.Fprintf(&b, "printf %s > %s\n", shellQuote(wantHosts), hostsPath)

	switch {
	case m == mgrResolved:
		fmt.Fprintf(&b, "mkdir -p %s\n", "/etc/systemd/resolved.conf.d")
		fmt.Fprintf(&b, "printf %s > %s\n",
			shellQuote(fmt.Sprintf("[Resolve]\nDNS=%s:%s\nDomains=~%s\n", resolverIP, resolverPort, Suffix)), resolvedDrop)
		b.WriteString("systemctl restart systemd-resolved\n")
	case dnsmasqPresent():
		fmt.Fprintf(&b, "mkdir -p %s\n", "/etc/dnsmasq.d")
		fmt.Fprintf(&b, "printf %s > %s\n",
			shellQuote(fmt.Sprintf("server=/%s/%s#%s\n", Suffix, resolverIP, resolverPort)), dnsmasqDrop)
		b.WriteString("systemctl restart dnsmasq 2>/dev/null || true\n")
	}

	what := "apply the sysctl, write the " + hostsPath + " block"
	if canRouteDomain(m, dnsmasqPresent()) {
		what += ", and route ." + Suffix + " to the resolver"
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
	fmt.Fprintf(&b, "rm -f %s %s %s\n", sysctlPath, resolvedDrop, dnsmasqDrop)
	fmt.Fprintf(&b, "printf %s > %s\n", shellQuote(stripped), hostsPath)
	b.WriteString("sysctl -q --system 2>/dev/null || true\n")
	// Restart BOTH: uninstall removes whichever drop-in was written, and the
	// daemon keeps serving the old config until it re-reads it. Leaving dnsmasq
	// pointing .doze at a resolver that is gone is a worse state than never
	// having configured it.
	b.WriteString("systemctl restart systemd-resolved 2>/dev/null || true\n")
	b.WriteString("systemctl restart dnsmasq 2>/dev/null || true\n")

	if err := runPrivileged(o, "remove the sysctl, the hosts block and the resolver route", b.String()); err != nil {
		return err
	}
	if !o.Print {
		fmt.Fprintln(o.out(), "✓ removed")
	}
	return nil
}
