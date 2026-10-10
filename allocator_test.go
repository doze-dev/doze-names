package names

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// Every test runs on the loopback network unless it says otherwise, so the
// suite means the same thing on a Mac as on Linux.
func init() { zone = loopbackNet }

// machine stands in a machine: its network, and which addresses can be used.
func machine(t *testing.T, n network, usable func(ip string) bool) {
	t.Helper()
	oldZone, oldBind := zone, canBind
	zone, canBind = n, usable
	t.Cleanup(func() { zone, canBind = oldZone, oldBind })
}

func all(string) bool  { return true }
func none(string) bool { return false }

func offsetOf(t *testing.T, ip net.IP) int {
	t.Helper()
	off, ok := zone.offset(ip)
	if !ok {
		t.Fatalf("%s is outside %s", ip, zone.cidr())
	}
	return off
}

func TestThePoolIsWideAndANameKeepsItsAddress(t *testing.T) {
	machine(t, loopbackNet, all)
	r := Open(t.TempDir(), "doze")
	seen := map[string]bool{}
	beyond := false
	for i := 0; i < 300; i++ {
		lease, err := r.Claim(Qualified(fmt.Sprintf("svc%d", i), "shop"))
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		off := offsetOf(t, lease.IP)
		if last := off & 0xff; off < dynamicBase || last == 0 || last == 255 {
			t.Fatalf("svc%d got %s, which is not an address a name may have", i, lease.IP)
		}
		if seen[lease.IP.String()] {
			t.Fatalf("%s was handed out twice", lease.IP)
		}
		seen[lease.IP.String()] = true
		beyond = beyond || off > 255
	}
	if !beyond {
		t.Fatal("300 services all fit in 127.0.0.x: the block is not being used")
	}
	// The same name asks again, from a fresh registry: the same address.
	a, _ := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	b, _ := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	if !a.IP.Equal(b.IP) {
		t.Fatalf("db.shop.doze got %s and then %s", a.IP, b.IP)
	}
}

// A name sits at the same place in the block on a Mac as on Linux; only the
// block differs.
func TestANameHasTheSameOffsetOnBothSystems(t *testing.T) {
	machine(t, loopbackNet, all)
	a, _ := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	offA := offsetOf(t, a.IP)
	machine(t, virtualNet, all)
	b, _ := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	if offB := offsetOf(t, b.IP); offA != offB {
		t.Fatalf("db.shop.doze is at offset %d on Linux and %d on a Mac", offA, offB)
	}
	if b.IP[0] != 198 || b.IP[1] != 19 {
		t.Fatalf("on a Mac db.shop.doze = %s, want an address in %s", b.IP, virtualNet.cidr())
	}
}

// A Mac with no setup: names still get the address their hash gives.
func TestNoSetupStillNamesAnAddress(t *testing.T) {
	machine(t, virtualNet, none)
	a, err := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	if PoolUsable() {
		t.Fatal("a machine whose daemon is down reports its pool usable")
	}
	machine(t, virtualNet, all)
	b, _ := Open(t.TempDir(), "doze").Claim(Qualified("db", "shop"))
	if !a.IP.Equal(b.IP) {
		t.Fatalf("with no setup db.shop.doze got %s; with setup %s — the hash should decide both", a.IP, b.IP)
	}
}

// Releasing a name gives its address back at once.
func TestAReleasedAddressIsReused(t *testing.T) {
	// One usable address, so the second claim can only succeed by reusing it.
	machine(t, loopbackNet, func(ip string) bool { return ip == "127.0.0.42" })
	r := Open(t.TempDir(), "doze")
	first, err := r.Claim(Qualified("old", "shop"))
	if err != nil || first.IP.String() != "127.0.0.42" {
		t.Fatalf("first claim = %v, %v; want 127.0.0.42", first, err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := r.Claim(Qualified("new", "shop"))
	if err != nil || second.IP.String() != "127.0.0.42" {
		t.Fatalf("after the release, the next claim got %v, %v; want the freed 127.0.0.42", second.IP, err)
	}
}

func TestClaimAtRefusesAnAddressInUse(t *testing.T) {
	machine(t, loopbackNet, all)
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
	machine(t, loopbackNet, all)
	taken := map[string]bool{}
	for slot := 0; slot < blockSlots; slot++ {
		taken[zone.at(slotOffset(slot)).String()] = true
	}
	free := zone.at(slotOffset(blockSlots - 7))
	delete(taken, free.String())
	if ip, err := addressFor(Qualified("last", "shop"), taken); err != nil || !ip.Equal(free) {
		t.Fatalf("with one address left the claim got %v, %v; want %s", ip, err, free)
	}
	taken[free.String()] = true
	if _, err := addressFor(Qualified("one-too-many", "shop"), taken); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("a claim on a full pool = %v, want an error saying it is in use", err)
	}
}

// On a machine with no setup every name resolves to 127.0.0.1. That address is
// shared on purpose and must never be refused, on either network.
func TestClaimAtSharesTheLoopbackAddress(t *testing.T) {
	for _, n := range []network{loopbackNet, virtualNet} {
		machine(t, n, all)
		r := Open(t.TempDir(), "doze")
		for _, svc := range []string{"db", "cache", "api"} {
			if _, err := r.ClaimAt(Qualified(svc, "shop"), net.ParseIP("127.0.0.1")); err != nil {
				t.Fatalf("%s at 127.0.0.1: %v", svc, err)
			}
		}
	}
}
