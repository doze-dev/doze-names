// Package names implements .doze, the local naming zone shared by every doze
// binary — the doze CLI, doze-aws and doze-kafka.
//
// The point of this package is that no binary owns the zone. Each one writes
// its names into a registry under the shared home, and whichever process binds
// the resolver socket first answers for ALL of them, its own and its peers'.
// Install order does not matter, no binary is a prerequisite for another, and
// if the serving process exits the next one takes the socket over.
//
// # Two tiers of name
//
// An apex name — aws.doze, kafka.doze — means "the one on this machine". It
// needs no stack, which is what makes it the right name for a standalone
// doze-aws or doze-kafka, and it is claimed first-come: a second claimant is
// told who holds it rather than silently taking or losing it.
//
// A qualified name — <service>.<stack>.doze — belongs to a doze CLI stack and
// is never contested, so a stack that loses the apex race still has a working
// address.
//
// # Addresses
//
// Every name resolves to its own loopback address rather than to a shared
// 127.0.0.1. That is what lets each service hold its canonical port — every
// Kafka on 9092, every local AWS on 80 — instead of a hand-picked high one, and
// it means http://aws.doze is the same URL whether a standalone process or a
// stack instance is behind it.
//
// Apex addresses are FIXED (see apexIP) rather than allocated, because on Linux
// they are written into /etc/hosts once at setup time, before anything is
// running. A static block never needs rewriting as services come and go, and
// when nothing is listening the name still resolves and the connection is
// refused — a truthful error rather than "no such host", which is what makes
// people suspect their DNS.
package names

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Suffix is the private TLD every doze name lives under.
const Suffix = "doze"

// The loopback range splits into a reserved head and a dynamic tail. Apex
// names take fixed addresses from the head so they can be written to
// /etc/hosts before any process exists; qualified names are placed in the tail.
//
// Note dynamicBase is 10, not 2: doze core's allocator started at 2, so the
// head has to be carved out of what it used to hand out. See the migration
// note in the spec — an apex claim must tolerate finding its address already
// taken by an older stack rather than binding something it does not own.
const (
	apexBase    = 2
	apexEnd     = 9
	dynamicBase = 10
	dynamicEnd  = 65
)

// resolverIP is where the resolver listens on Linux. It is NOT 127.0.0.53:
// that is systemd-resolved's own stub listener, and binding it would fight the
// system resolver. Excluded from the dynamic range below.
const resolverIP = "127.0.0.54"

// apexIP is the fixed address of each well-known service. Adding an entry here
// is a compatibility commitment: it goes into people's /etc/hosts.
var apexIP = map[string]string{
	"aws":   "127.0.0.2",
	"kafka": "127.0.0.3",
	// 127.0.0.4-9 held for postgres, valkey, … as they arrive.
}

// Tier distinguishes a machine-wide name from a stack's own.
type Tier string

const (
	TierApex      Tier = "apex"
	TierQualified Tier = "qualified"
)

// Name is a host in the doze zone.
type Name struct {
	Host string
	Tier Tier
}

// Apex returns the machine-wide name for a service: Apex("aws") → aws.doze.
func Apex(service string) Name {
	return Name{Host: label(service) + "." + Suffix, Tier: TierApex}
}

// Qualified returns a stack service's name: Qualified("cloud", "shop") →
// cloud.shop.doze.
func Qualified(service, stack string) Name {
	return Name{Host: label(service) + "." + label(stack) + "." + Suffix, Tier: TierQualified}
}

func (n Name) String() string { return n.Host }

// service returns the first label — the key into apexIP for an apex name.
func (n Name) service() string {
	if i := strings.Index(n.Host, "."); i >= 0 {
		return n.Host[:i]
	}
	return n.Host
}

// InZone reports whether a host belongs to the doze zone.
func InZone(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == Suffix || strings.HasSuffix(host, "."+Suffix)
}

// label sanitizes one DNS label: lowercase, [a-z0-9-], no leading or trailing
// dash. Matches doze core's DomainLabel so a name means the same thing in both.
func label(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// addressFor picks the loopback address a name should resolve to. Apex names
// are looked up in the fixed table; qualified names are hashed into the dynamic
// range so the same name lands on the same address run after run without
// anything having to be persisted. taken lets the caller exclude addresses
// live peers already hold.
func addressFor(n Name, taken map[string]bool) (net.IP, error) {
	if n.Tier == TierApex {
		ip, ok := apexIP[n.service()]
		if !ok {
			return nil, fmt.Errorf("no reserved address for apex name %q "+
				"(add it to apexIP — the value is a compatibility commitment)", n.Host)
		}
		return net.ParseIP(ip), nil
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(n.Host))
	span := dynamicEnd - dynamicBase + 1
	start := int(h.Sum32()%uint32(span)) + dynamicBase
	// Probe forward so a collision with a live peer shifts rather than fails.
	for i := 0; i < span; i++ {
		octet := dynamicBase + (start-dynamicBase+i)%span
		ip := fmt.Sprintf("127.0.0.%d", octet)
		if ip == resolverIP || taken[ip] {
			continue
		}
		return net.ParseIP(ip), nil
	}
	return nil, fmt.Errorf("loopback range 127.0.0.%d-%d is full", dynamicBase, dynamicEnd)
}

// ResolverAddr is where the resolver listens, which differs by platform
// because the two OSes route a TLD differently.
//
// macOS routes a whole TLD with a port via /etc/resolver/doze, so the resolver
// can sit on an unprivileged high port. Linux has no such hook: the route is a
// systemd-resolved or dnsmasq drop-in, and neither reliably accepts a port, so
// the resolver takes port 53 on an address of its own. Binding 53 unprivileged
// is what the sysctl drop-in in setup is for.
func ResolverAddr() string {
	if runtime.GOOS == "linux" {
		return resolverIP + ":53"
	}
	return "127.0.0.1:5323"
}

// EnvHome overrides the shared doze home, matching doze core's variable.
const EnvHome = "DOZE_HOME"

// Home is the directory the binaries share. They have to agree on it or they
// will not see each other's names, so it is resolved here rather than in each
// of them: $DOZE_HOME, else ~/.doze.
func Home() string {
	if h := os.Getenv(EnvHome); h != "" {
		return h
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "." + Suffix
	}
	return filepath.Join(h, "."+Suffix)
}
