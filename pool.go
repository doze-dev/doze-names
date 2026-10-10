package names

// Where a name's address comes from.
//
// A zone address is a two-octet base plus an offset. The offset is what a name
// owns: 2 to 9 are the fixed apex addresses, and everything from 10 up is
// hashed. The base is the machine's, and there are two of them.
//
// On Linux and Windows the base is 127.0: all of 127.0.0.0/8 is local there,
// so a service binds its address directly and nothing has to run for it.
//
// On macOS it is 198.19, and no service binds its address at all. A loopback
// address exists on a Mac only once it has been aliased onto lo0, and aliasing
// them in bulk is not survivable: measured on macOS 27, 250 more took
// mDNSResponder to 100% of a core and a name lookup from 10 ms to over a
// second, 4,000 took a lookup to 150 seconds, and configd was killed by its
// watchdog. So setup installs a small daemon (see netd_darwin.go) that owns one
// interface with the whole block routed to it, and a service listens on a
// private port that the daemon translates its address to. One interface and
// one address, however many services there are.
//
// 198.18.0.0/15 is set aside for benchmarking (RFC 2544) and never routed on a
// real network. Other tools on a developer's Mac use it for the same reason,
// which is why this takes the lower half of 198.19 and not all of it: OrbStack
// has 198.19.248.0/22 and proxy tools default to 198.18.0.0/16.

import (
	"fmt"
	"hash/fnv"
	"net"
	"runtime"
)

const (
	apexBase    = 2
	apexEnd     = 9
	dynamicBase = 10

	// The block is a /17: third octets 0 to 127. The last octet of an address
	// is never 0 or 255, which leaves 254 to each third octet.
	blockThirds = 128
	perThird    = 254
	blockSlots  = blockThirds * perThird
	blockPrefix = 17
)

// network is how this machine gives a name an address.
type network struct {
	a, b byte
	// virtual means no service can bind its address: the block is routed to
	// the daemon's interface, and Lease.Listen registers a private port.
	virtual bool
}

var (
	loopbackNet = network{a: 127, b: 0}
	virtualNet  = network{a: 198, b: 19, virtual: true}
)

// zone is this machine's network. A variable so a test can stand in either.
var zone = func() network {
	if runtime.GOOS == "darwin" {
		return virtualNet
	}
	return loopbackNet
}()

// at returns the address at an offset into the block.
func (n network) at(offset int) net.IP {
	return net.IPv4(n.a, n.b, byte(offset>>8), byte(offset)).To4()
}

// offset returns an address's offset into the block, and whether it is in it.
func (n network) offset(ip net.IP) (int, bool) {
	v4 := ip.To4()
	if v4 == nil || v4[0] != n.a || v4[1] != n.b || v4[2] >= blockThirds {
		return 0, false
	}
	return int(v4[2])<<8 | int(v4[3]), true
}

// gateway is the daemon's own address, and where a service's private port is
// listened on. Only a virtual network has one.
func (n network) gateway() net.IP { return n.at(1) }

// cidr is the block, as the route to it is written.
func (n network) cidr() string { return fmt.Sprintf("%d.%d.0.0/%d", n.a, n.b, blockPrefix) }

// slotOffset turns one of the block's slots into an offset: 254 addresses to
// each third octet, .1 to .254.
func slotOffset(slot int) int { return (slot/perThird)<<8 | (slot%perThird + 1) }

// apexOffset is the fixed offset of each well-known service. Adding an entry
// here is a compatibility commitment: on Linux it goes into people's
// /etc/hosts.
var apexOffset = map[string]int{
	"aws":   2,
	"kafka": 3,
	// 4-9 held for postgres, valkey, … as they arrive.
}

// apexAddr is the fixed address of a well-known service on this machine.
func apexAddr(service string) (net.IP, bool) {
	off, ok := apexOffset[service]
	if !ok {
		return nil, false
	}
	return zone.at(off), true
}

// canBind reports whether a service can be given this address right now. On
// Linux that is whether it can be listened on, which every 127.x.y.z address
// can. On macOS it is whether the daemon is up, since the address itself is
// never bound. A variable so a test can stand in a machine of its choosing.
var canBind = func(ip string) bool {
	if zone.virtual {
		return gatewayUp()
	}
	l, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// gatewayUp reports whether the daemon's interface exists. The interface lives
// exactly as long as the daemon holds it open, so this is also whether the
// daemon is running.
func gatewayUp() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	gw := zone.gateway()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(gw) {
			return true
		}
	}
	return false
}

// addressFor picks the address a name should resolve to. Apex names are looked
// up in the fixed table; qualified names are hashed into the block so the same
// name lands on the same address run after run without anything having to be
// persisted. taken lets the caller exclude addresses live peers already hold.
//
// It prefers an address this machine can use. If none of the free ones can be
// — macOS before setup — it falls back to the hash alone, so the name still
// has an address and the caller learns the rest when it tries to listen, which
// is how every caller already handles a machine that is not set up.
func addressFor(n Name, taken map[string]bool) (net.IP, error) {
	if n.Tier == TierApex {
		ip, ok := apexAddr(n.service())
		if !ok {
			return nil, fmt.Errorf("no reserved address for apex name %q "+
				"(add it to apexOffset — the value is a compatibility commitment)", n.Host)
		}
		return ip, nil
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(n.Host))
	start := int(h.Sum32() % uint32(blockSlots))
	// Probe forward so a collision with a live peer shifts rather than fails.
	var firstFree net.IP
	for i := 0; i < blockSlots; i++ {
		off := slotOffset((start + i) % blockSlots)
		if off < dynamicBase {
			continue
		}
		ip := zone.at(off)
		if taken[ip.String()] {
			continue
		}
		if canBind(ip.String()) {
			return ip, nil
		}
		if firstFree == nil {
			firstFree = ip
		}
		if zone.virtual {
			break // the daemon is down: no other address will do better
		}
	}
	if firstFree != nil {
		return firstFree, nil
	}
	return nil, fmt.Errorf("every address in %s is in use by a running doze service", zone.cidr())
}

// inPool reports whether ip is one of the addresses this package hands out.
func inPool(ip net.IP) bool {
	off, ok := zone.offset(ip)
	return ok && off >= apexBase
}

// PoolUsable reports whether this machine can give a service an address of its
// own. It is true on Linux, and on macOS once setup has installed the daemon
// and it is running. When it is false, everything listens on 127.0.0.1 and two
// services cannot share a port.
func PoolUsable() bool { return canBind(zone.at(dynamicBase).String()) }
