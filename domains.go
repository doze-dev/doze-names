package names

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Your own domain. A stack can give an app a name outside the doze zone —
// dev.acme.com, or every subdomain of it — because sign-in providers send a
// browser back only to a name under a public top-level domain, over https.
// The name is an entry in the same registry as the .doze names, with the
// same liveness, the same address as the app's .doze name (Lease.Twin), and
// the same front door routing it by Host; what differs is how the machine
// is told to ask this resolver for it (a per-domain route, see trust_*.go)
// and that the front door serves it over TLS from the doze CA (ca.go).

// TierDomain marks an entry for a name outside the doze zone.
const TierDomain Tier = "domain"

// ValidDomain says whether host can be a domain of an app: lowercase DNS
// labels, at least two of them, optionally one leading wildcard label; not
// in the doze zone, not localhost, not an address.
func ValidDomain(host string) error {
	h := normalize(host)
	if h == "" {
		return errors.New("a domain cannot be empty")
	}
	if net.ParseIP(h) != nil {
		return fmt.Errorf("%q is an address, not a domain", host)
	}
	if InZone(h) {
		return fmt.Errorf("%q is a doze name already; domains are for names outside .%s", host, Suffix)
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return fmt.Errorf("%q: browsers and sign-in providers treat localhost specially; use a real domain", host)
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q has no top-level domain; a domain needs at least two labels", host)
	}
	for i, l := range labels {
		if l == "*" {
			if i != 0 {
				return fmt.Errorf("%q: a wildcard can only be the first label", host)
			}
			continue
		}
		if l == "" || l != label(l) || len(l) > 63 {
			return fmt.Errorf("%q: %q is not a DNS label (lowercase letters, digits and hyphens)", host, l)
		}
	}
	if labels[0] == "*" && len(labels) < 3 {
		return fmt.Errorf("%q: a wildcard needs a domain under it", host)
	}
	return nil
}

// DomainName is the registry name for a domain.
func DomainName(host string) Name { return Name{Host: normalize(host), Tier: TierDomain} }

// Wildcard says a domain stands for every name under it.
func Wildcard(host string) bool { return strings.HasPrefix(normalize(host), "*.") }

// RouteDomain is the name a machine route is installed for: the domain
// itself, or what a wildcard is under. /etc/resolver/<this> covers the
// name and everything beneath it.
func RouteDomain(host string) string { return strings.TrimPrefix(normalize(host), "*.") }

// lookupDomain finds the domain entry that owns a host outside the doze
// zone: the exact name, else a wildcard over it. A wildcard owns every
// depth under it for resolving and routing; its certificate covers one
// level, as certificates do.
func lookupDomain(m map[string]Entry, host string) (Entry, bool) {
	h := normalize(host)
	if e, ok := m[h]; ok && e.Tier == TierDomain {
		return e, true
	}
	for {
		_, rest, found := strings.Cut(h, ".")
		if !found || !strings.Contains(rest, ".") {
			return Entry{}, false
		}
		if e, ok := m["*."+rest]; ok && e.Tier == TierDomain {
			return e, true
		}
		h = rest
	}
}

// IsDomain reports whether a Host header names a domain this machine
// serves: the front door redirects those to https.
func (r *Registry) IsDomain(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if InZone(host) {
		return false
	}
	_, ok := lookupDomain(r.Snapshot(), host)
	return ok
}

// Domains lists the domains registered on this machine, newest claim last
// is not promised: sorted by name, for the trust script and doctor.
func (r *Registry) Domains() []string {
	var out []string
	for host, e := range r.Snapshot() {
		if e.Tier == TierDomain {
			out = append(out, host)
		}
	}
	sortStrings(out)
	return out
}

// RouteDomains is Domains with wildcards folded onto what they are under,
// without repeats: one machine route each.
func RouteDomains(domains []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range domains {
		rd := RouteDomain(d)
		if !seen[rd] {
			seen[rd] = true
			out = append(out, rd)
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}

// Certificate says a domain is served with the person's own certificate and
// key files rather than one minted from the doze CA. The files are read at
// each handshake that needs them, so a renewed file is picked up.
func (l *Lease) Certificate(certFile, keyFile string) error {
	if l == nil || l.reg == nil {
		return nil
	}
	return l.reg.update(func(m map[string]Entry) error {
		e, ok := m[l.Name.Host]
		if !ok || e.PID != l.reg.pid {
			return fmt.Errorf("%s is not held by this process", l.Name.Host)
		}
		e.Cert, e.Key = certFile, keyFile
		m[l.Name.Host] = e
		return nil
	})
}

// CheckCertificate reads a certificate the person brought and says whether
// it will do for a domain: parses, covers the name (and, for a wildcard,
// the names under it), and has not expired. The error is for doctor.
func CheckCertificate(certFile, keyFile, domain string) (expires time.Time, err error) {
	crt, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", certFile, err)
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", certFile, err)
	}
	probe := normalize(domain)
	if Wildcard(domain) {
		probe = "probe." + RouteDomain(domain)
	}
	if err := leaf.VerifyHostname(probe); err != nil {
		return leaf.NotAfter, fmt.Errorf("%s does not cover %s: %w", certFile, domain, err)
	}
	if time.Now().After(leaf.NotAfter) {
		return leaf.NotAfter, fmt.Errorf("%s expired on %s", certFile, leaf.NotAfter.Format("2006-01-02"))
	}
	return leaf.NotAfter, nil
}
