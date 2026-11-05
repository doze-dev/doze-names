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
// the System keychain as a trusted root for TLS; Safari and Chrome read it,
// and Firefox 120 and later do too.

const systemKeychain = "/Library/Keychains/System.keychain"

func platformTrust() error { return nil }

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

// routesScript writes a file for every route to keep that is not there,
// and removes the files of the routes to drop. Domains were validated
// (ValidDomain) before they reached a record or a config, and are quoted
// anyway.
func routesScript(keep, drop []string) string {
	_, port, _ := net.SplitHostPort(ResolverAddr())
	lines := []string{"mkdir -p /etc/resolver"}
	for _, d := range keep {
		if routed, _ := domainRouted(d); !routed {
			lines = append(lines, fmt.Sprintf("printf 'nameserver 127.0.0.1\\nport %s\\n' > %s", port, shellQuote(resolverFileFor(d))))
		}
	}
	for _, d := range drop {
		lines = append(lines, "rm -f "+shellQuote(resolverFileFor(d)))
	}
	return strings.Join(lines, "\n")
}

// caTrusted asks the keychain for a root with this fingerprint.
func caTrusted(ca *CA) (bool, string) {
	if ok, _ := fingerprintTrusted(ca.Fingerprint()); ok {
		return true, "trusted in the System keychain · " + ca.Subject() + " · expires " + ca.NotAfter().Format("2006-01-02")
	}
	return false, "not trusted · " + ca.RootPath()
}

// fingerprintTrusted says whether a root with this SHA-256 is in the
// System keychain.
func fingerprintTrusted(fp string) (bool, string) {
	out, err := exec.Command("security", "find-certificate", "-a", "-Z", "-c", caCommonName, systemKeychain).Output()
	if err == nil && strings.Contains(strings.ToUpper(string(out)), strings.ToUpper(fp)) {
		return true, fp
	}
	return false, fp
}

func trustScript(ca *CA) string {
	// Trusted for TLS and basic certificate chaining only, as mkcert does:
	// never for code signing or mail.
	return fmt.Sprintf("security add-trusted-cert -d -r trustRoot -p ssl -p basic -k %s %s", systemKeychain, shellQuote(ca.RootPath()))
}

func untrustScript(ca *CA) string { return untrustFingerprintScript(ca.Fingerprint()) }

// untrustFingerprintScript removes one root by its SHA-256, and its trust
// settings with it (-t).
func untrustFingerprintScript(fp string) string {
	return fmt.Sprintf("security delete-certificate -t -Z %s %s 2>/dev/null || true", shellQuote(fp), systemKeychain)
}
