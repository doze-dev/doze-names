package names

import (
	"io"
	"net"
	"strconv"
	"testing"
)

// translatedLoopback is a network whose addresses are translated, like a
// Mac's, but whose gateway is 127.0.0.1 — so the registering half of Listen
// runs on any machine, with no daemon.
var translatedLoopback = network{a: 127, b: 0, virtual: true}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Where an address is local, Listen binds it.
func TestListenBindsTheAddressWhereItCan(t *testing.T) {
	machine(t, loopbackNet, all)
	r := Open(t.TempDir(), "doze")
	lease, err := r.ClaimAt(Qualified("db", "shop"), net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	ln, err := lease.Listen(port)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := ln.Addr().(*net.TCPAddr); !got.IP.Equal(lease.IP) || got.Port != port {
		t.Fatalf("listening on %s, want %s:%d", got, lease.IP, port)
	}
	if e := r.Snapshot()["db.shop.doze"]; len(e.Ports) != 0 {
		t.Fatalf("a bound address registered ports: %v", e.Ports)
	}
}

// Where it is not, two services take the same public port, each on a private
// one, and the table the daemon translates from has both.
func TestListenRegistersAPrivatePortWhereItCannot(t *testing.T) {
	machine(t, translatedLoopback, all)
	home := t.TempDir()
	r := Open(home, "doze")
	var leases []*Lease
	var lns []net.Listener
	for _, stack := range []string{"shop", "blog"} {
		lease, err := r.Claim(Qualified("db", stack))
		if err != nil {
			t.Fatal(err)
		}
		ln, err := lease.Listen(5432)
		if err != nil {
			t.Fatalf("db.%s on 5432: %v", stack, err)
		}
		if got := ln.Addr().String(); got != lease.IP.String()+":5432" {
			t.Fatalf("db.%s says it listens on %s, want its public address %s:5432", stack, got, lease.IP)
		}
		leases, lns = append(leases, lease), append(lns, ln)
	}

	table := readPortTable(r.Path(), zone)
	for i, lease := range leases {
		var v [4]byte
		copy(v[:], lease.IP.To4())
		private, ok := table.private(v, 5432)
		if !ok {
			t.Fatalf("%s:5432 is not in the table", lease.Name)
		}
		if public, ok := table.public(v, private); !ok || public != 5432 {
			t.Fatalf("%s: private port %d maps back to %d, %v", lease.Name, private, public, ok)
		}
		// The private port is the listener: what is sent there arrives.
		go func() {
			c, err := lns[i].Accept()
			if err == nil {
				io.WriteString(c, lease.Name.Host)
				c.Close()
			}
		}()
		c, err := net.Dial("tcp", net.JoinHostPort(zone.gateway().String(), strconv.Itoa(int(private))))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(c)
		c.Close()
		if string(got) != lease.Name.Host {
			t.Fatalf("private port of %s answered %q", lease.Name, got)
		}
	}

	// Claiming the name again, as doze does on every topology change, keeps it.
	if _, err := r.ClaimAt(leases[0].Name, leases[0].IP); err != nil {
		t.Fatal(err)
	}
	if e := r.Snapshot()[leases[0].Name.Host]; e.Ports["5432"] == 0 {
		t.Fatal("re-claiming a name dropped its ports")
	}

	// Closing takes the registration with it.
	lns[0].Close()
	if e := r.Snapshot()[leases[0].Name.Host]; len(e.Ports) != 0 {
		t.Fatalf("a closed listener is still registered: %v", e.Ports)
	}
	lns[1].Close()
}

// A routed name is served on port 80 by the front door, unless the service
// listens on 80 itself.
func TestARoutedNameIsServedByTheFrontDoor(t *testing.T) {
	machine(t, translatedLoopback, all)
	r := Open(t.TempDir(), "doze")
	api, _ := r.Claim(Qualified("api", "shop"))
	aws, _ := r.Claim(Qualified("aws", "shop"))
	db, _ := r.Claim(Qualified("db", "shop"))
	_ = api.Route("127.0.0.1:3000")
	_ = aws.Route("127.0.0.1:4566")
	_ = aws.Forward(80, 4566)
	addr := func(l *Lease) (v [4]byte) { copy(v[:], l.IP.To4()); return }

	if _, ok := readPortTable(r.Path(), zone).private(addr(api), 80); ok {
		t.Fatal("port 80 is forwarded with no front door running")
	}
	r.claimIngress(ingressBind)
	table := readPortTable(r.Path(), zone)
	if p, ok := table.private(addr(api), 80); !ok || p != 80 {
		t.Fatalf("api.shop.doze:80 → %d, %v; want the front door on 80", p, ok)
	}
	if p, _ := table.private(addr(aws), 80); p != 4566 {
		t.Fatalf("aws.shop.doze:80 → %d; want its own listener on 4566", p)
	}
	if _, ok := table.private(addr(db), 80); ok {
		t.Fatal("a name with no route is forwarded to the front door")
	}
}

// A caller with an address and no lease gets the same listener.
func TestRegistryListenFindsTheNameByItsAddress(t *testing.T) {
	machine(t, translatedLoopback, all)
	r := Open(t.TempDir(), "doze")
	lease, err := r.Claim(Qualified("db", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := r.Listen(net.JoinHostPort(lease.IP.String(), "5432"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if e := r.Snapshot()["db.shop.doze"]; e.Ports["5432"] == 0 {
		t.Fatalf("listening by address registered nothing: %+v", e)
	}
	if _, err := r.Listen(net.JoinHostPort(zone.at(99<<8|9).String(), "5432")); err == nil {
		t.Fatal("listened on an address no name of this program has")
	}
	// An address outside the block is listened on as it is.
	plain, err := r.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	plain.Close()
}

// A service that restarts comes back on a different private port at the same
// address. The first connection after that must go to the new one, not to the
// port the last run had — which nothing listens on any more.
func TestTheTableFollowsAServiceThatRestarted(t *testing.T) {
	machine(t, translatedLoopback, all)
	r := Open(t.TempDir(), "doze")
	lease, err := r.Claim(Qualified("db", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	var v [4]byte
	copy(v[:], lease.IP.To4())
	if err := lease.Forward(5432, 51885); err != nil {
		t.Fatal(err)
	}
	c := newTableCache(r.Path(), zone)
	if p, _ := c.current().private(v, 5432); p != 51885 {
		t.Fatalf("before the restart 5432 → %d", p)
	}

	if err := lease.Forward(5432, 52094); err != nil {
		t.Fatal(err)
	}
	c.refresh(false) // what a new connection does
	if p, _ := c.current().private(v, 5432); p != 52094 {
		t.Fatalf("after the restart 5432 → %d, want the new port 52094", p)
	}
	if _, ok := c.current().public(v, 51885); ok {
		t.Fatal("the old private port still maps back to 5432")
	}

	// Nothing written: nothing rebuilt.
	before := c.current()
	c.refresh(false)
	if c.current() != before {
		t.Fatal("the table was rebuilt though the registry had not changed")
	}
}
