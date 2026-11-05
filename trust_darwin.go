package names

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// macOS: a route is a file in /etc/resolver named after the domain, which
// the system consults for that name and everything under it (resolver(5)),
// the same way /etc/resolver/doze routes the zone. The authority goes into
// the System keychain as a trusted root; Safari and Chrome read it, and
// Firefox 120 and later do too.

const systemKeychain = "/Library/Keychains/System.keychain"

func resolverFileFor(domain string) string { return "/etc/resolver/" + domain }

func domainRouted(domain string) (bool, string) {
	raw, err := os.ReadFile(resolverFileFor(domain))
	_, port, _ := net.SplitHostPort(ResolverAddr())
	if err != nil {
		return false, resolverFileFor(domain) + " missing — " + domain + " will not resolve here"
	}
	s := string(raw)
	if strings.Contains(s, "127.0.0.1") && strings.Contains(s, port) {
		return true, resolverFileFor(domain) + " → " + ResolverAddr()
	}
	return false, resolverFileFor(domain) + " points elsewhere"
}

func routeScript(domain string) string {
	_, port, _ := net.SplitHostPort(ResolverAddr())
	return fmt.Sprintf("mkdir -p /etc/resolver\nprintf 'nameserver 127.0.0.1\\nport %s\\n' > %s", port, shellQuote(resolverFileFor(domain)))
}

func unrouteScript(domain string) string {
	return "rm -f " + shellQuote(resolverFileFor(domain))
}

// caTrusted asks the keychain for a root with this fingerprint.
func caTrusted(ca *CA) (bool, string) {
	out, err := exec.Command("security", "find-certificate", "-a", "-Z", "-c", ca.Subject(), systemKeychain).Output()
	if err == nil && strings.Contains(strings.ToUpper(string(out)), strings.ToUpper(ca.Fingerprint())) {
		return true, "trusted in the System keychain · " + ca.Subject() + " · expires " + ca.NotAfter().Format("2006-01-02")
	}
	return false, "not trusted · " + ca.RootPath()
}

func trustScript(ca *CA) string {
	return fmt.Sprintf("security add-trusted-cert -d -r trustRoot -k %s %s", systemKeychain, shellQuote(ca.RootPath()))
}

func untrustScript(ca *CA) string {
	return fmt.Sprintf("security delete-certificate -Z %s %s 2>/dev/null || true", ca.Fingerprint(), systemKeychain)
}
