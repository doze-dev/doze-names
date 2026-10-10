package names

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// freeAddr returns a loopback host:port nothing is listening on.
func freeAddr(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().String()
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// A zone given its own home, DNS address and front-door address touches
// nothing of the machine's real one: this is what lets the tools be tested
// together on a machine where the real zone is in use.
func TestAPrivateZone(t *testing.T) {
	dns, front := freeAddr(t, "udp"), freeAddr(t, "tcp")
	t.Setenv(EnvResolver, dns)
	t.Setenv(EnvIngress, front)
	if ResolverAddr() != dns || IngressBind() != front {
		t.Fatalf("resolver %s, front door %s; want %s and %s", ResolverAddr(), IngressBind(), dns, front)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from "+r.Host)
	}))
	defer backend.Close()

	reg := Open(t.TempDir(), "doze")
	lease, err := reg.Claim(Qualified("api", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Route(strings.TrimPrefix(backend.URL, "http://")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv := Serve(ctx, reg, nil)
	defer srv.Close()
	in := ServeIngress(ctx, reg, nil)
	defer in.Close()
	if !srv.Bound(ctx) || !in.Bound(ctx) {
		t.Fatal("the private zone's servers did not bind their own addresses")
	}

	// DNS, asked of the private server.
	if got := queryA(t, dns, "api.shop.doze"); got != lease.IP.String() {
		t.Fatalf("api.shop.doze resolved to %q through the private server, want %s", got, lease.IP)
	}
	// The front door, on its private port, routed by Host.
	req, _ := http.NewRequest("GET", "http://"+front+"/", nil)
	req.Host = "api.shop.doze"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from api.shop.doze" {
		t.Fatalf("front door answered %q", body)
	}
	// And the URL it advertises carries the port a client has to use.
	_, port, _ := net.SplitHostPort(front)
	if got, want := reg.URLFor("api.shop.doze"), "http://api.shop.doze:"+port; got != want {
		t.Fatalf("URLFor = %q, want %q", got, want)
	}
}

// queryA asks a DNS server for a name's A record and returns the address, or
// "" for no answer.
func queryA(t *testing.T, server, host string) string {
	t.Helper()
	conn, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(host, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root, type A, class IN
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no answer from %s: %v", server, err)
	}
	if n < len(q)+16 || buf[7] == 0 { // no answer records
		return ""
	}
	a := buf[n-4 : n]
	return net.IPv4(a[0], a[1], a[2], a[3]).String()
}
