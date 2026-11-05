package names

import (
	"context"
	"encoding/binary"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeUpstream stands in for the machine's DNS servers: it answers every A
// question with 203.0.113.9, cached for an hour as a real host's answer
// would be, and the resolver under test forwards to it. asked lists the
// names it was sent.
func fakeUpstream(t *testing.T) (asked func() []string) {
	t.Helper()
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	var names []string
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := up.ReadFromUDP(buf)
			if err != nil {
				return
			}
			name, _, _, _ := parseQuestion(buf[:n], 12)
			mu.Lock()
			names = append(names, name)
			mu.Unlock()
			resp, _ := answer(buf[:n], func(string) net.IP { return net.IPv4(203, 0, 113, 9) })
			if len(resp) >= 10 {
				binary.BigEndian.PutUint32(resp[len(resp)-10:], 3600)
			}
			_, _ = up.WriteToUDP(resp, addr)
		}
	}()
	old := upstreamAddrs
	upstreamAddrs = func() []string { return []string{up.LocalAddr().String()} }
	t.Cleanup(func() { upstreamAddrs = old })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), names...)
	}
}

// With doze fully down, a routed domain pointed at a port nobody listened
// on, so the real host was unreachable until a stack came up. The network
// daemon holds the resolver then: the zone is NXDOMAIN, a routed domain
// nobody declares is the internet's, a stack that comes up is answered from
// the registry without anything restarting, and its own resolver stands by
// behind the daemon and takes over when the daemon goes.
func TestTheNetworkDaemonAnswersTheZoneWhenNoProgramDoes(t *testing.T) {
	asked := fakeUpstream(t)
	addr := freeUDPAddr(t)
	t.Setenv(EnvResolver, addr)
	home := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	netd := serveZone(ctx, filepath.Join(home, FileName), t.Logf)
	if !netd.Bound(waitCtx(t)) {
		t.Fatal("the daemon never took the resolver")
	}
	answerOf := func(name string) net.IP {
		resp := ask(t, addr, name)
		if ancountOf(resp) != 1 {
			return nil
		}
		return net.IP(resp[len(resp)-4:])
	}

	// Nothing runs: the zone is nobody's and the routed domain is the internet's.
	if rcode := rcodeOf(ask(t, addr, "web.shop.doze")); rcode != 3 {
		t.Errorf("with nothing running, web.shop.doze rcode = %d, want NXDOMAIN", rcode)
	}
	if ip := answerOf("dev.acme.com"); !ip.Equal(net.IPv4(203, 0, 113, 9)) {
		t.Errorf("with nothing running, dev.acme.com = %v, want the upstream's answer", ip)
	}
	if h, ok := Open(home, "doze").ResolverHolder(); !ok || h.Owner != netdOwner {
		t.Errorf("the registry names the daemon as the resolver: %+v, %v", h, ok)
	}

	// A stack comes up and declares the domain: answered from the registry
	// at once, by the daemon, with nothing restarted.
	r := Open(home, "doze")
	web, err := r.Claim(Qualified("web", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = web.Release() }()
	if _, err := web.Twin(DomainName("dev.acme.com")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dev.acme.com", "web.shop.doze"} {
		if ip := answerOf(name); !ip.Equal(web.IP) {
			t.Errorf("with the stack up, %s = %v, want the app's %v", name, ip, web.IP)
		}
	}

	// The stack's own resolver stands by behind the daemon, as behind any
	// peer, and takes over when the daemon is restarted.
	peer := ServeAt(ctx, r, addr, t.Logf)
	defer peer.Close()
	brief, cancelBrief := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancelBrief()
	if peer.Bound(brief) {
		t.Fatal("a program took the resolver from the daemon")
	}
	netd.Close()
	if !peer.Bound(waitCtx(t)) {
		t.Fatal("the program never took over from the daemon")
	}
	if ip := answerOf("web.shop.doze"); !ip.Equal(web.IP) {
		t.Errorf("after the take-over, web.shop.doze = %v, want %v", ip, web.IP)
	}
	if got := asked(); len(got) != 1 || got[0] != "dev.acme.com" {
		t.Errorf("the upstream was asked %v, want dev.acme.com once, while nothing declared it", got)
	}
}
