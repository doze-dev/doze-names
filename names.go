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
// Every name resolves to an address of its own rather than to a shared
// 127.0.0.1 (see pool.go for where the addresses come from). That is what lets each service hold its canonical port — every
// Kafka on 9092, every local AWS on 80 — instead of a hand-picked high one, and
// it means http://aws.doze is the same URL whether a standalone process or a
// stack instance is behind it.
//
// Apex addresses are FIXED (see apexOffset) rather than allocated, because on Linux
// they are written into /etc/hosts once at setup time, before anything is
// running. A static block never needs rewriting as services come and go, and
// when nothing is listening the name still resolves and the connection is
// refused — a truthful error rather than "no such host", which is what makes
// people suspect their DNS.
package names

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Suffix is the private TLD every doze name lives under.
const Suffix = "doze"

// resolverIP is where the resolver listens on Linux — deliberately NOT a
// loopback address.
//
// systemd-resolved refuses loopback addresses as DNS servers outright
// ("Invalid DNS server address"), and refuses the loopback interface too
// ("Link lo is loopback device"), so there is no way to point it at anything on
// 127.0.0.x. Setup therefore gives the resolver an address of its own on a
// dummy interface, which is structurally what Tailscale does with
// 100.100.100.100.
//
// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved for documentation and
// guaranteed never to appear on a real network — so a /32 out of it cannot
// collide with anything the machine legitimately routes to.
const (
	resolverIP    = "192.0.2.53"
	resolverIface = "doze0"
)

// resolverPort is the port the resolver listens on. Deliberately NOT 53.
//
// Port 53 is unavailable on the machines that matter most: systemd-resolved
// holds it on the WILDCARD, which takes every address on that port with it, so
// 127.0.0.54:53 cannot be bound at all — measured on Ubuntu with systemd 255,
// where 0.0.0.0:53, 127.0.0.53:53 and 127.0.0.54:53 were all in use.
//
// An earlier draft chose 53 to avoid needing a port in the resolver config,
// believing neither systemd-resolved nor dnsmasq would take one reliably. Both
// do — systemd-resolved since v249 (DNS=addr:port), dnsmasq via
// server=/zone/addr#port — and the port that actually cannot be had is 53.
// Using a high port also takes the privileged-port sysctl off the DNS path
// entirely; it is still needed for the :80 front door.
const resolverPort = "5323"

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

// ResolverAddr is where the resolver listens, which differs by platform
// because the two OSes route a TLD differently.
//
// macOS routes a whole TLD via /etc/resolver/doze, so the resolver sits on
// loopback there. Linux has no such hook, and systemd-resolved will not accept
// a loopback server at all, so the resolver takes its own non-loopback address
// on a dummy interface that setup creates. Both platforms use a high port: 53
// is held on the wildcard by whatever already serves DNS.
func ResolverAddr() string {
	if a := strings.TrimSpace(os.Getenv(EnvResolver)); a != "" {
		return a
	}
	if runtime.GOOS == "linux" {
		return resolverIP + ":" + resolverPort
	}
	return "127.0.0.1:" + resolverPort
}

// EnvResolver and EnvIngress move the zone's two shared sockets, for a zone
// that must not touch the machine's real one: a test, or two zones side by
// side. Together with EnvHome they make a zone private — its own registry, its
// own DNS server, its own front door. Every program in that zone has to be
// given the same three values, exactly as every program in the real zone
// agrees on the defaults. The operating system's resolver knows nothing of a
// private zone; its names resolve only for a client that asks its DNS server.
const (
	EnvResolver = "DOZE_ZONE_RESOLVER" // host:port for the DNS server, e.g. 127.0.0.1:15323
	EnvIngress  = "DOZE_ZONE_INGRESS"  // host:port for the HTTP front door, e.g. 127.0.0.1:18080
)

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

// EnvZone turns the zone off for every doze binary at once: DOZE_ZONE=off (or 0,
// false, no). One switch rather than a flag per binary, so a CI job or a container
// that has no use for names says so once.
const EnvZone = "DOZE_ZONE"

// Disabled reports whether the zone has been switched off with DOZE_ZONE.
func Disabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvZone))) {
	case "off", "0", "false", "no":
		return true
	}
	return false
}

// Reachable reports whether something accepts a TCP connection at host:port, so a
// caller prints a by-name address only if it answers. A name that does not resolve,
// or resolves to an address nothing listens on, is not worth telling anyone.
func Reachable(host string, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), reachableWait)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

const reachableWait = 400 * time.Millisecond
