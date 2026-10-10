package names

// The network daemon, for real: on a Mac that setup has been run on. It needs
// root to have installed the daemon, so it runs only when asked for
// (DOZE_NAMES_E2E=1), which CI does on a machine that is thrown away after.
// Never on a developer's own machine — an earlier measurement there is why.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func e2e(t *testing.T) *Registry {
	t.Helper()
	if os.Getenv("DOZE_NAMES_E2E") == "" {
		t.Skip("needs a machine with the network daemon installed; set DOZE_NAMES_E2E=1 on one that can be thrown away")
	}
	usable := canBindReal
	if foreground() {
		usable = func(string) bool { return gatewayPresent() }
	}
	machine(t, virtualNet, usable)
	if !PoolUsable() {
		t.Fatalf("the network daemon is not running:\n%s", Check())
	}
	var lim syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim) == nil && lim.Cur < 20000 {
		lim.Cur = 20000
		if lim.Max < lim.Cur {
			lim.Cur = lim.Max
		}
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
	return Open(Home(), "e2e")
}

// foreground reports a daemon started by hand for this run (DOZE_NAMES_E2E=foreground)
// and not installed: no launchd job, and a home of the test's own, so nothing
// of the machine's real zone is touched. What needs the installed daemon or
// the system resolver is skipped.
func foreground() bool { return os.Getenv("DOZE_NAMES_E2E") == "foreground" }

// canBindReal is canBind as it is outside the tests.
var canBindReal = canBind

// mdns is mDNSResponder's CPU share right now, and how long the system
// resolver takes to answer for a name.
func mdns() (cpu float64, lookup time.Duration) {
	out, _ := exec.Command("ps", "-axo", "pcpu=,comm=").Output()
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.HasSuffix(f[1], "/mDNSResponder") {
			v, _ := strconv.ParseFloat(f[0], 64)
			cpu += v
		}
	}
	start := time.Now()
	_ = exec.Command("dscacheutil", "-q", "host", "-a", "name", "localhost").Run()
	return cpu, time.Since(start)
}

// serveName answers every connection with the name it was listening for.
func serveName(ln net.Listener, name string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			_, _ = io.WriteString(c, name)
			_ = c.Close()
		}()
	}
}

func askAddr(addr string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	return string(b), err
}

// The point of the daemon: thousands of services, every one on the same port
// at an address of its own, and the machine none the worse for it.
func TestNetworkThousandsOfServicesOnOnePort(t *testing.T) {
	r := e2e(t)
	const services = 2000

	cpu0, look0 := mdns()
	addrs0, _ := net.InterfaceAddrs()

	start := time.Now()
	leases := make([]*Lease, services)
	for i := range leases {
		lease, err := r.Claim(Qualified("db", fmt.Sprintf("stack%d", i)))
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		ln, err := lease.Listen(5432)
		if err != nil {
			t.Fatalf("%s on 5432: %v", lease.Name, err)
		}
		defer ln.Close()
		go serveName(ln, lease.Name.Host)
		leases[i] = lease
	}
	t.Logf("%d services registered on port 5432 in %s", services, time.Since(start).Round(time.Millisecond))

	start = time.Now()
	for _, lease := range leases {
		got, err := askAddr(net.JoinHostPort(lease.IP.String(), "5432"))
		if err != nil || got != lease.Name.Host {
			t.Fatalf("%s:5432 answered %q, %v; want %s", lease.IP, got, err, lease.Name.Host)
		}
	}
	each := time.Since(start) / services
	t.Logf("every one answered as itself; a connect, an answer and a close took %s on average", each)

	time.Sleep(5 * time.Second) // let anything that was going to react, react
	cpu1, look1 := mdns()
	addrs1, _ := net.InterfaceAddrs()
	t.Logf("mDNSResponder: %.1f%% CPU before, %.1f%% after; a lookup took %s before, %s after",
		cpu0, cpu1, look0.Round(time.Millisecond), look1.Round(time.Millisecond))
	t.Logf("addresses on the machine's interfaces: %d before, %d after", len(addrs0), len(addrs1))
	if len(addrs1) != len(addrs0) {
		t.Errorf("registering services changed the machine's addresses (%d → %d): the daemon exists so that it does not", len(addrs0), len(addrs1))
	}
	if cpu1 > 50 || look1 > time.Second {
		t.Errorf("the machine is suffering: mDNSResponder at %.1f%%, a lookup at %s", cpu1, look1)
	}
}

func TestNetworkARefusedPortIsRefusedAtOnce(t *testing.T) {
	r := e2e(t)
	lease, err := r.Claim(Qualified("db", "refused"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ln, err := lease.Listen(5432)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	for _, addr := range []string{
		net.JoinHostPort(lease.IP.String(), "6379"),           // a port it does not serve
		net.JoinHostPort(zone.at(120<<8|77).String(), "5432"), // an address nobody has
	} {
		start := time.Now()
		_, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "refused") {
			t.Errorf("dial %s = %v, want connection refused", addr, err)
		}
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("dial %s took %s to fail: a closed port should refuse at once", addr, d)
		}
	}
}

func TestNetworkPing(t *testing.T) {
	r := e2e(t)
	lease, err := r.Claim(Qualified("db", "ping"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	out, err := exec.Command("ping", "-c", "2", "-t", "3", lease.IP.String()).CombinedOutput()
	if err != nil {
		t.Fatalf("ping %s: %v\n%s", lease.IP, err, out)
	}
}

// By name, the way a person uses it: the system resolver finds the address,
// a database-style port is reached on it, and the bare http:// URL is served
// by the front door.
func TestNetworkByName(t *testing.T) {
	r := e2e(t)
	if foreground() {
		t.Skip("uses the system resolver and the machine's real zone")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dns, front := Serve(ctx, r, t.Logf), ServeIngress(ctx, r, t.Logf)
	defer dns.Close()
	defer front.Close()
	wait, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	if !dns.Bound(wait) || !front.Bound(wait) {
		t.Fatal("could not take the zone's DNS socket and front door")
	}

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go http.Serve(backend, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "api for %s from %s", req.Host, req.Header.Get("X-Forwarded-For"))
	}))

	api, err := r.Claim(Qualified("api", "byname"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Release()
	if err := api.Route(backend.Addr().String()); err != nil {
		t.Fatal(err)
	}
	db, err := r.Claim(Qualified("db", "byname"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Release()
	ln, err := db.Listen(5432)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveName(ln, db.Name.Host)

	ips, err := net.LookupHost(db.Name.Host)
	if err != nil || len(ips) != 1 || ips[0] != db.IP.String() {
		t.Fatalf("the system resolver says %s is %v, %v; want %s", db.Name, ips, err, db.IP)
	}
	if got, err := askAddr(db.Name.Host + ":5432"); err != nil || got != db.Name.Host {
		t.Fatalf("%s:5432 answered %q, %v", db.Name, got, err)
	}

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + api.Name.Host + "/")
	if err != nil {
		t.Fatalf("GET http://%s/: %v", api.Name, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "api for "+api.Name.Host) {
		t.Fatalf("GET http://%s/ = %d %q", api.Name, resp.StatusCode, body)
	}
	t.Logf("http://%s/ → %q", api.Name, body)
}

// pump sends size bytes to addr and returns how fast they went, in Gbit/s.
func pump(t *testing.T, ln net.Listener, addr string, size int64) float64 {
	t.Helper()
	got := make(chan int64, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- 0
			return
		}
		n, _ := io.Copy(io.Discard, c)
		c.Close()
		got <- n
	}()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1<<20)
	start := time.Now()
	for sent := int64(0); sent < size; sent += int64(len(buf)) {
		if _, err := c.Write(buf); err != nil {
			t.Fatalf("after %d bytes: %v", sent, err)
		}
	}
	c.Close()
	if n := <-got; n != size {
		t.Fatalf("sent %d bytes, %d arrived", size, n)
	}
	return float64(size) * 8 / time.Since(start).Seconds() / 1e9
}

// What going through the daemon costs, against plain loopback.
func TestNetworkThroughput(t *testing.T) {
	r := e2e(t)
	const size = 1 << 30

	direct, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	loop := pump(t, direct, direct.Addr().String(), size)

	lease, err := r.Claim(Qualified("bulk", "speed"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ln, err := lease.Listen(9000)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	through := pump(t, ln, ln.Addr().String(), size)

	t.Logf("1 GiB over plain loopback: %.1f Gbit/s; through the daemon: %.1f Gbit/s", loop, through)
	if through < 0.5 {
		t.Errorf("%.2f Gbit/s through the daemon is too slow to be a database's network", through)
	}
}

// The daemon is restarted under a listening service and an open, idle
// connection. Reported, not required: this is to learn what a tool has to do
// when the daemon comes back.
func TestNetworkDaemonRestart(t *testing.T) {
	r := e2e(t)
	if foreground() {
		t.Skip("restarts the installed daemon")
	}
	lease, err := r.Claim(Qualified("db", "restart"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ln, err := lease.Listen(5432)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	conns := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-conns
	defer server.Close()

	if out, err := exec.Command("sudo", "launchctl", "kickstart", "-k", "system/"+launchdLabel).CombinedOutput(); err != nil {
		t.Fatalf("restart the daemon: %v\n%s", err, out)
	}
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 100 && !gatewayUp(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if !gatewayUp() {
		t.Fatal("the daemon did not come back")
	}
	time.Sleep(500 * time.Millisecond)

	// The connection that was open across the restart.
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_, werr := client.Write([]byte("still here"))
	buf := make([]byte, 16)
	n, rerr := server.Read(buf)
	t.Logf("a connection open across the restart: write %v, read %q %v", werr, buf[:n], rerr)

	// The listener that was open across the restart.
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	t.Logf("a listener open across the restart: a new connection gives %v", err)
	if err == nil {
		c.Close()
	}

	// A listener opened after it.
	again, err := lease.Listen(5433)
	if err != nil {
		t.Fatalf("listen after the restart: %v", err)
	}
	defer again.Close()
	go serveName(again, "after")
	if got, err := askAddr(again.Addr().String()); err != nil || got != "after" {
		t.Fatalf("a listener opened after the restart answered %q, %v", got, err)
	}
}

// A service stops and starts again at once, as a restart does: same address,
// same public port, a private port that is different. The very next connection
// has to reach the new listener. A daemon that translated from a table it had
// read a moment before sent it to the old port, which nothing listened on.
func TestNetworkAServiceThatRestarts(t *testing.T) {
	r := e2e(t)
	lease, err := r.Claim(Qualified("db", "again"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	for i := 0; i < 50; i++ {
		ln, err := lease.Listen(5432)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("run %d", i)
		go serveName(ln, name)
		got, err := askAddr(ln.Addr().String())
		ln.Close()
		if err != nil || got != name {
			t.Fatalf("restart %d: the first connection answered %q, %v; want %q", i, got, err, name)
		}
	}
}
