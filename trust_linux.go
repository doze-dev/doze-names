package names

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Linux: the routes are the link's domain list in systemd-resolved, one
// setting that holds the zone and every domain together, so it is always
// restated whole: at runtime with resolvectl, and in a drop-in of the zone
// unit so a reboot sets it again. Machines without resolved have no route
// for a domain; the name works with its port. The authority goes into the
// distribution's bundle: Debian's update-ca-certificates or Fedora's
// update-ca-trust, whichever is there.

const routesDropIn = "/etc/systemd/system/" + unitName + ".d/domains.conf"

func platformTrust() error { return nil }

// linkDomains is the link's domain list as resolved reports it, one token
// each ("~doze", "~dev.acme.com").
func linkDomains() []string {
	out, err := exec.Command("resolvectl", "domain", resolverIface).Output()
	if err != nil {
		return nil
	}
	_, rest, _ := strings.Cut(string(out), ":")
	return strings.Fields(rest)
}

func domainRouted(domain string) (bool, string) {
	if detect() != mgrResolved {
		return false, domain + " needs systemd-resolved to be routed; use the name with its port"
	}
	for _, tok := range linkDomains() {
		if tok == "~"+domain {
			return true, "resolved sends " + domain + " to " + resolverIP + ":" + resolverPort
		}
	}
	return false, domain + " is not routed to the doze resolver"
}

// routeForeign: a resolved route is doze's own setting on doze's own link,
// so nothing here is anyone else's.
func routeForeign(string) bool { return false }

// routesScript sets the link's domain list to the zone plus every route to
// keep, now and at boot. The routes to write are in keep already; the
// dropped ones are simply not in it. The live setting fails harmlessly when
// the link is not up (the drop-in still sets it at the next boot).
func routesScript(keep, _, _ []string) string {
	toks := []string{"~" + Suffix}
	for _, d := range keep {
		toks = append(toks, "~"+d)
	}
	list := strings.Join(toks, " ")
	unit := fmt.Sprintf("[Service]\nExecStart=-/usr/bin/resolvectl domain %s %s\n", resolverIface, list)
	return strings.Join([]string{
		fmt.Sprintf("resolvectl domain %s %s 2>/dev/null || true", resolverIface, list),
		"mkdir -p " + shellQuote(strings.TrimSuffix(routesDropIn, "/domains.conf")),
		"printf '%s' " + shellQuote(unit) + " > " + shellQuote(routesDropIn),
		"systemctl daemon-reload 2>/dev/null || true",
	}, "\n")
}

// uninstallRoutesScript: the zone's link and its drop-in go with the zone
// (setup_linux.go), and the routes with them; nothing is restated.
func uninstallRoutesScript([]string) string { return "" }

func caBundlePath() (path, update string) {
	if _, err := os.Stat("/etc/pki/ca-trust/source/anchors"); err == nil {
		return "/etc/pki/ca-trust/source/anchors/doze-local-ca.crt", "update-ca-trust"
	}
	return "/usr/local/share/ca-certificates/doze-local-ca.crt", "update-ca-certificates"
}

func caTrusted(ca *CA) (bool, string) {
	path, _ := caBundlePath()
	cur, err := os.ReadFile(path)
	want, err2 := os.ReadFile(ca.RootPath())
	if err == nil && err2 == nil && string(cur) == string(want) {
		return true, "trusted in the system bundle · " + path
	}
	return false, "not trusted · " + ca.RootPath()
}

// fingerprintTrusted: the bundle holds one doze root at a time (cp -f), so a
// rotated-out root is gone with the rotation.
func fingerprintTrusted(*CA, string) (bool, string) { return false, "" }

func trustedDozeRoots() []string { return nil }

func trustScript(ca *CA) string {
	path, update := caBundlePath()
	return fmt.Sprintf("cp -f %s %s\n%s", shellQuote(ca.RootPath()), shellQuote(path), update)
}

func untrustScript(*CA) string {
	path, update := caBundlePath()
	return fmt.Sprintf("rm -f %s\n%s", shellQuote(path), update)
}

func untrustFingerprintScript(*CA, string) string { return "" }

// untrustUnknownScript removes whatever doze root the bundle holds; the
// file is doze's by name, so no fingerprint is needed.
func untrustUnknownScript() []string { return []string{untrustScript(nil)} }

func platformRootsPEM() []byte { return nil }
