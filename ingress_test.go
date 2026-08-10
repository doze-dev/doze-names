package names

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestURLIsPortlessOnlyWhenDozeHoldsTheFrontDoor(t *testing.T) {
	// The distinction that matters: something else on :80 answers doze names
	// with its own content, so reporting a port-less URL would send people to
	// the wrong service. A TCP dial cannot tell the difference; the registry
	// can.
	home := t.TempDir()
	reg := Open(home, "doze-aws")
	lease, err := reg.Claim(Apex("aws"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Route("127.0.0.2:4566"); err != nil {
		t.Fatal(err)
	}

	if got := reg.URLFor("aws.doze"); got != "http://aws.doze:4566" {
		t.Errorf("with no doze front door, URLFor = %q, want the port-ful URL", got)
	}

	reg.claimIngress(IngressAddr)
	if got := reg.URLFor("aws.doze"); got != "http://aws.doze" {
		t.Errorf("with a doze front door, URLFor = %q, want port-less", got)
	}

	reg.releaseIngress()
	if got := reg.URLFor("aws.doze"); got != "http://aws.doze:4566" {
		t.Errorf("after release, URLFor = %q, want the port-ful URL again", got)
	}
}

func TestIngressBookkeepingIsNotARoute(t *testing.T) {
	// The holder is stored in the registry alongside the names; it must not
	// leak into what the front door claims to serve.
	reg := Open(t.TempDir(), "doze")
	reg.claimIngress(IngressAddr)
	for _, line := range routed(reg) {
		if line != "  (nothing — no doze service has registered a route)" {
			t.Errorf("ingress bookkeeping surfaced as a route: %q", line)
		}
	}
	if ip := reg.Resolve(ingressKey); ip != nil {
		t.Errorf("ingress bookkeeping resolved as a name: %v", ip)
	}
}

func TestFrontDoorProxiesByHostAndPreservesIt(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusTeapot)
	}))
	defer backend.Close()

	reg := Open(t.TempDir(), "doze-aws")
	lease, err := reg.Claim(Apex("aws"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Route(backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	front := httptest.NewServer(proxy(reg))
	defer front.Close()

	req, _ := http.NewRequestWithContext(context.Background(), "GET", front.URL, nil)
	req.Host = "aws.doze"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want the backend's 418", resp.StatusCode)
	}
	// doze-aws builds the URLs it returns from this header, so a queue created
	// through aws.doze has to report an aws.doze URL.
	if gotHost != "aws.doze" {
		t.Errorf("backend saw Host %q, want aws.doze", gotHost)
	}

	// A name nobody fronts is a 404 that says what IS fronted, because the
	// usual cause is a service that is not running.
	req2, _ := http.NewRequestWithContext(context.Background(), "GET", front.URL, nil)
	req2.Host = "nope.doze"
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("unfronted name = %d, want 404", resp2.StatusCode)
	}
}

func TestFrontDoorContendsOnIPv4(t *testing.T) {
	// Listening on ":80" takes the IPv6 wildcard, and macOS grants it even when
	// another program holds IPv4 0.0.0.0:80 — so the bind succeeds, no client
	// ever reaches the socket, and we would record ourselves as fronting while
	// the other program served every doze name. Observed exactly that.
	//
	// Every name in the zone is a 127.0.0.x address, so IPv4 is the family that
	// matters and the one to contend for.
	if ingressNetwork != "tcp4" {
		t.Errorf("ingressNetwork = %q, want tcp4 — see the comment above", ingressNetwork)
	}
	if ingressBind != "0.0.0.0:80" {
		t.Errorf("ingressBind = %q, want the IPv4 wildcard", ingressBind)
	}

	// And prove the property on an arbitrary port: holding IPv4 must make our
	// bind fail rather than succeed on a socket nobody can reach.
	held, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skip("cannot bind an IPv4 wildcard here")
	}
	defer held.Close()
	_, port, _ := net.SplitHostPort(held.Addr().String())

	if second, err := net.Listen(ingressNetwork, "0.0.0.0:"+port); err == nil {
		second.Close()
		t.Error("a second IPv4 wildcard bind succeeded; contention is not real")
	} else if !isAddrInUse(err) {
		t.Errorf("second bind failed with %v, want address-in-use", err)
	}
}
