package names

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

// machine stands in a machine on which only some of the pool can be bound.
func machine(t *testing.T, bindable func(octet int) bool) {
	t.Helper()
	old, oldEnd := canBind, poolEnd
	poolEnd = dynamicEnd // the wide range, unless a test narrows it with mac()
	canBind = func(ip string) bool {
		octet, err := strconv.Atoi(ip[strings.LastIndex(ip, ".")+1:])
		return err == nil && bindable(octet)
	}
	t.Cleanup(func() { canBind, poolEnd = old, oldEnd })
}

// mac stands in a Mac after setup: .2 to .65 aliased, and names hashed there.
func mac(t *testing.T) {
	t.Helper()
	machine(t, func(o int) bool { return o >= apexBase && o <= macAliasEnd })
	poolEnd = macAliasEnd
}

func lastOctet(ip net.IP) int { return int(ip.To4()[3]) }

func TestThePoolRunsTo254AndANameKeepsItsAddress(t *testing.T) {
	machine(t, func(int) bool { return true }) // Linux: the whole range is local
	r := Open(t.TempDir(), "doze")
	seen := map[int]bool{}
	high := false
	for i := 0; i < 120; i++ {
		lease, err := r.Claim(Qualified(fmt.Sprintf("svc%d", i), "shop"))
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		o := lastOctet(lease.IP)
		if o < dynamicBase || o > dynamicEnd {
			t.Fatalf("svc%d got 127.0.0.%d, outside %d-%d", i, o, dynamicBase, dynamicEnd)
		}
		if seen[o] {
			t.Fatalf("127.0.0.%d was handed out twice", o)
		}
		seen[o] = true
		high = high || o > macAliasEnd
	}
	if !high {
		t.Fatalf("120 services all fit below .%d: the wider pool is not being used", macAliasEnd)
	}
	// The same name asks again, from a fresh registry: the same address.
	a, _ := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	b, _ := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	if !a.IP.Equal(b.IP) {
		t.Fatalf("db.shop.doze got %s and then %s", a.IP, b.IP)
	}
}

// A Mac has only .2 to .65 aliased. Everything handed out there must be an
// address it can actually listen on.
func TestAMacGetsOnlyWhatItHasAliased(t *testing.T) {
	mac(t)
	r := Open(t.TempDir(), "doze")
	n := macAliasEnd - dynamicBase + 1
	for i := 0; i < n; i++ {
		lease, err := r.Claim(Qualified(fmt.Sprintf("svc%d", i), "shop"))
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		if o := lastOctet(lease.IP); o > macAliasEnd {
			t.Fatalf("svc%d got 127.0.0.%d, which this machine cannot bind", i, o)
		}
	}
	// A Mac's share is used up, and the claim says so rather than naming an
	// address the machine does not have.
	if _, err := r.Claim(Qualified("one-too-many", "shop")); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("the 57th service on a Mac = %v, want an error saying the pool is in use", err)
	}
}

// On a Mac names are hashed into the part of the range the machine has, so
// each lands on an address of its own choosing rather than all of them sliding
// to the lowest free one.
func TestAMacSpreadsNamesAcrossItsRange(t *testing.T) {
	mac(t)
	distinct := map[int]bool{}
	for _, n := range []string{"db", "cache", "api", "web", "events", "cloud", "worker", "auth"} {
		l, _ := Open(t.TempDir(), "doze").Claim(Qualified(n, "shop"))
		distinct[lastOctet(l.IP)] = true
	}
	if len(distinct) < 5 {
		t.Fatalf("eight names hashed to only %d addresses: they are sliding to the lowest free one", len(distinct))
	}
}

// A machine with no setup at all (macOS, fresh): names still get the address
// their hash gives, as they always have.
func TestNoSetupStillNamesAnAddress(t *testing.T) {
	machine(t, func(int) bool { return false })
	a, err := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	machine(t, func(int) bool { return true })
	b, _ := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	if !a.IP.Equal(b.IP) {
		t.Fatalf("with no setup db.shop.doze got %s; with setup %s — the hash should decide both", a.IP, b.IP)
	}
}

// Releasing a name gives its address back at once.
func TestAReleasedAddressIsReused(t *testing.T) {
	// One usable address, so the second claim can only succeed by reusing it.
	machine(t, func(o int) bool { return o == 42 })
	r := Open(t.TempDir(), "doze")
	first, err := r.Claim(Qualified("old", "shop"))
	if err != nil || lastOctet(first.IP) != 42 {
		t.Fatalf("first claim = %v, %v; want 127.0.0.42", first, err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := r.Claim(Qualified("new", "shop"))
	if err != nil || lastOctet(second.IP) != 42 {
		t.Fatalf("after the release, the next claim got %v, %v; want the freed 127.0.0.42", second.IP, err)
	}
}

func TestClaimAtRefusesAnAddressInUse(t *testing.T) {
	machine(t, func(int) bool { return true })
	r := Open(t.TempDir(), "doze")
	db, err := r.Claim(Qualified("db", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ClaimAt(Qualified("cache", "shop"), db.IP)
	var taken *ErrAddrTaken
	if !errors.As(err, &taken) || taken.Host != "db.shop.doze" {
		t.Fatalf("claiming db's address for cache = %v, want ErrAddrTaken naming db.shop.doze", err)
	}
	// The holder itself may claim it again, and a free address is fine.
	if _, err := r.ClaimAt(Qualified("db", "shop"), db.IP); err != nil {
		t.Fatalf("re-claiming one's own address: %v", err)
	}
	if _, err := r.ClaimAt(Qualified("cache", "shop"), net.ParseIP("127.0.0.200")); err != nil {
		t.Fatalf("claiming a free address: %v", err)
	}
}

func TestAFullPoolSaysSo(t *testing.T) {
	machine(t, func(int) bool { return true })
	r := Open(t.TempDir(), "doze")
	for i := 0; i < dynamicEnd-dynamicBase+1; i++ {
		if _, err := r.Claim(Qualified(fmt.Sprintf("svc%d", i), "shop")); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
	}
	_, err := r.Claim(Qualified("one-too-many", "shop"))
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("the 246th service = %v, want an error saying the pool is in use", err)
	}
}

// On a machine with no setup every name resolves to 127.0.0.1. That address is
// shared on purpose and must never be refused.
func TestClaimAtSharesTheLoopbackAddress(t *testing.T) {
	r := Open(t.TempDir(), "doze")
	for _, svc := range []string{"db", "cache", "api"} {
		if _, err := r.ClaimAt(Qualified(svc, "shop"), net.ParseIP("127.0.0.1")); err != nil {
			t.Fatalf("%s at 127.0.0.1: %v", svc, err)
		}
	}
}
