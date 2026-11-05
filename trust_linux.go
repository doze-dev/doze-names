package names

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Linux: a route is one more domain resolved sends to the doze0 link, set
// at runtime with resolvectl and kept in the zone unit's drop-in so it
// survives a reboot; the hosts-file machines (no resolved) get the apex
// name only, as the zone does. The authority goes into the distribution's
// bundle: Debian's update-ca-certificates or Fedora's update-ca-trust,
// whichever is there.

const routesDropIn = "/etc/systemd/system/doze-zone.service.d/domains.conf"

func domainRouted(domain string) (bool, string) {
	if detect() != mgrResolved {
		return false, domain + " needs systemd-resolved to be routed; use the name with its port"
	}
	out, err := exec.Command("resolvectl", "domain", resolverIface).Output()
	if err == nil && strings.Contains(string(out), "~"+domain) {
		return true, "resolved sends " + domain + " to " + resolverIP + ":" + resolverPort
	}
	return false, domain + " is not routed to the doze resolver"
}

func routeScript(domain string) string {
	// Current domains plus this one, so the drop-in restates the whole set.
	return fmt.Sprintf(`resolvectl domain %[1]s $(resolvectl domain %[1]s 2>/dev/null | sed 's/^.*: //') ~%[2]s
mkdir -p %[3]s
grep -q -- '~%[2]s' %[4]s 2>/dev/null || printf '[Service]\nExecStart=-/usr/bin/resolvectl domain %[1]s ~%[2]s\n' >> %[4]s`,
		resolverIface, domain, shellQuote(strings.TrimSuffix(routesDropIn, "/domains.conf")), routesDropIn)
}

func unrouteScript(domain string) string {
	return fmt.Sprintf(`sed -i '/~%[2]s$/d' %[1]s 2>/dev/null || true
resolvectl domain %[3]s $(resolvectl domain %[3]s 2>/dev/null | sed 's/^.*: //' | sed 's/~%[2]s//') 2>/dev/null || true`,
		routesDropIn, domain, resolverIface)
}

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

func trustScript(ca *CA) string {
	path, update := caBundlePath()
	return fmt.Sprintf("cp -f %s %s\n%s", shellQuote(ca.RootPath()), shellQuote(path), update)
}

func untrustScript(ca *CA) string {
	path, update := caBundlePath()
	return fmt.Sprintf("rm -f %s\n%s", shellQuote(path), update)
}
