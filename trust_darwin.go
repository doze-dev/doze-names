package names

import (
	"crypto/x509"
	"encoding/pem"
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
//
// Trust is checked the way the keychain checks it, with verify-cert, not by
// whether the certificate is present: a root can be in the keychain and
// not trusted, or trusted and then not. The basic policy is the one a root
// passes when trusted (the ssl policy demands transparency logs of a root
// given as a leaf, so it fails for every root, public ones included).
// Removal uses remove-trusted-cert -d, which takes the certificate file:
// delete-certificate -t removes user trust settings only, and the root was
// trusted in the admin store.

const systemKeychain = "/Library/Keychains/System.keychain"

func platformTrust() error { return nil }

func resolverFileFor(domain string) string { return "/etc/resolver/" + domain }

// routeFileState reads a domain's resolver file: ours (points at this
// resolver), foreign (someone else's file), or absent.
func routeFileState(domain string) (ours, present bool) {
	raw, err := os.ReadFile(resolverFileFor(domain))
	if err != nil {
		return false, false
	}
	_, port, _ := net.SplitHostPort(ResolverAddr())
	s := string(raw)
	return strings.Contains(s, "127.0.0.1") && strings.Contains(s, port), true
}

func domainRouted(domain string) (bool, string) {
	ours, present := routeFileState(domain)
	switch {
	case ours:
		return true, resolverFileFor(domain) + " → " + ResolverAddr()
	case present:
		return false, resolverFileFor(domain) + " is someone else's and points elsewhere; doze leaves it alone — remove it to let doze route " + domain
	}
	return false, resolverFileFor(domain) + " missing — " + domain + " will not resolve here"
}

// routeForeign says a file that is not doze's routes the domain: it is
// never written over or removed.
func routeForeign(domain string) bool {
	ours, present := routeFileState(domain)
	return present && !ours
}

// routesScript writes a file for each route in write, and removes the
// files of the routes in drop; keep (the whole set the machine should
// hold) is Linux's concern, where the list is one setting. Only doze's
// own files are touched. Domains were validated (ValidDomain) before they
// reached a record or a config, and are quoted anyway.
func routesScript(_, write, drop []string) string {
	_, port, _ := net.SplitHostPort(ResolverAddr())
	var lines []string
	for _, d := range write {
		if routeForeign(d) {
			continue
		}
		if len(lines) == 0 {
			lines = append(lines, "mkdir -p /etc/resolver")
		}
		lines = append(lines, fmt.Sprintf("printf 'nameserver 127.0.0.1\\nport %s\\n' > %s", port, shellQuote(resolverFileFor(d))))
	}
	for _, d := range drop {
		if routeForeign(d) {
			continue
		}
		lines = append(lines, "rm -f "+shellQuote(resolverFileFor(d)))
	}
	return strings.Join(lines, "\n")
}

// uninstallRoutesScript removes every recorded route's file when the zone
// itself is being removed.
func uninstallRoutesScript(routes []string) string { return routesScript(nil, nil, routes) }

// rootTrusted asks the keychain whether a root certificate file is trusted
// as an anchor on this machine.
func rootTrusted(certFile string) bool {
	return exec.Command("security", "verify-cert", "-L", "-l", "-q", "-p", "basic", "-c", certFile).Run() == nil
}

// caTrusted says whether the authority is trusted here.
func caTrusted(ca *CA) (bool, string) {
	if rootTrusted(ca.RootPath()) {
		return true, "trusted in the System keychain · " + ca.Subject() + " · expires " + ca.NotAfter().Format("2006-01-02")
	}
	return false, "not trusted · " + ca.RootPath()
}

// fingerprintTrusted says whether a rotated-out root is still trusted:
// by evaluation when its file was kept, else by its presence in the
// System keychain.
func fingerprintTrusted(ca *CA, fp string) (bool, string) {
	if !validFingerprint(fp) {
		return false, fp
	}
	if ca != nil {
		if _, err := os.Stat(ca.previousPath(fp)); err == nil {
			return rootTrusted(ca.previousPath(fp)), fp
		}
	}
	for _, have := range trustedDozeRoots() {
		if strings.EqualFold(have, fp) {
			return true, fp
		}
	}
	return false, fp
}

// trustedDozeRoots lists the SHA-256 fingerprints of every doze authority
// in the System keychain, trusted or not: what a removal must cover when
// the files that made them are gone.
func trustedDozeRoots() []string {
	out, err := exec.Command("security", "find-certificate", "-a", "-Z", "-c", caCommonName, systemKeychain).Output()
	if err != nil {
		return nil
	}
	var fps []string
	for _, line := range strings.Split(string(out), "\n") {
		if _, v, ok := strings.Cut(strings.TrimSpace(line), "SHA-256 hash:"); ok {
			if fp := strings.ToLower(strings.TrimSpace(v)); validFingerprint(fp) {
				fps = appendUnique(fps, fp)
			}
		}
	}
	return fps
}

func trustScript(ca *CA) string {
	// Trusted for TLS and basic certificate chaining only, as mkcert does:
	// never for code signing or mail.
	return fmt.Sprintf("security add-trusted-cert -d -r trustRoot -p ssl -p basic -k %s %s", systemKeychain, shellQuote(ca.RootPath()))
}

func untrustScript(ca *CA) string { return untrustRootScript(ca.RootPath(), ca.Fingerprint()) }

// untrustFingerprintScript removes a rotated-out root: its admin trust
// by file when the file was kept, and the certificate itself by hash.
func untrustFingerprintScript(ca *CA, fp string) string {
	file := ""
	if ca != nil {
		file = ca.previousPath(fp)
	}
	return untrustRootScript(file, fp)
}

func untrustRootScript(file, fp string) string {
	var lines []string
	if file != "" {
		if _, err := os.Stat(file); err == nil {
			lines = append(lines, "security remove-trusted-cert -d "+shellQuote(file)+" 2>/dev/null || true")
		}
	}
	if validFingerprint(fp) {
		lines = append(lines, fmt.Sprintf("security delete-certificate -t -Z %s %s 2>/dev/null || true", shellQuote(fp), systemKeychain))
	}
	return strings.Join(lines, "\n")
}

// untrustUnknownScript removes every doze authority the keychain holds,
// for when the files that would name them are gone or unreadable.
func untrustUnknownScript() []string {
	var out []string
	for _, fp := range trustedDozeRoots() {
		out = append(out, untrustRootScript("", fp))
	}
	return out
}

// platformRootsPEM is Apple's curated file of the system roots trusted for
// TLS (the keychain of system roots holds more, some distrusted), plus any
// authority an administrator put in the System keychain and trusted: a
// corporate root. A certificate that is merely present there, such as the
// machine's own identities, is not an anchor and is left out.
func platformRootsPEM() []byte {
	var out []byte
	if b, err := os.ReadFile("/etc/ssl/cert.pem"); err == nil {
		out = append(out, b...)
	} else if b, err := exec.Command("security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain").Output(); err == nil {
		out = append(out, b...)
	}
	if b, err := exec.Command("security", "find-certificate", "-a", "-p", systemKeychain).Output(); err == nil {
		out = append(out, trustedAnchorsIn(b)...)
	}
	return out
}

// trustedAnchorsIn keeps the certificate authorities in a PEM bundle that
// this machine trusts as roots, leaving out leaves, identities, anything
// present but not trusted, and doze's own.
func trustedAnchorsIn(pemBytes []byte) []byte {
	var out []byte
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !crt.IsCA || strings.HasPrefix(crt.Subject.CommonName, caCommonName) {
			continue
		}
		one := pem.EncodeToMemory(block)
		f, err := os.CreateTemp("", "doze-anchor-*.pem")
		if err != nil {
			continue
		}
		_, _ = f.Write(one)
		_ = f.Close()
		if rootTrusted(f.Name()) {
			out = append(out, one...)
		}
		_ = os.Remove(f.Name())
	}
}
