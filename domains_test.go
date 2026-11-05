package names

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidDomainAcceptsNamesUnderAPublicTLDAndRefusesTheRest(t *testing.T) {
	for _, ok := range []string{"dev.acme.com", "*.dev.acme.com", "app.acme.co.uk", "DEV.Acme.com."} {
		if err := ValidDomain(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "acme", "localhost", "app.localhost", "web.shop.doze", "127.0.0.1", "a.*.com", "*.com", "under_score.com", "-dash.com"} {
		if err := ValidDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if RouteDomain("*.dev.acme.com") != "dev.acme.com" || RouteDomain("dev.acme.com") != "dev.acme.com" {
		t.Error("the route is the domain under the wildcard")
	}
	if got := RouteDomains([]string{"*.dev.acme.com", "dev.acme.com", "api.acme.com"}); len(got) != 2 || got[0] != "api.acme.com" || got[1] != "dev.acme.com" {
		t.Errorf("RouteDomains = %v", got)
	}
}

func TestADomainIsTheAppsTwinAndAnswersForItsSubtree(t *testing.T) {
	home := t.TempDir()
	r := Open(home, "doze")
	web, err := r.Claim(Qualified("web", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = web.Release() })
	dom, err := web.Twin(DomainName("dev.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	wild, err := web.Twin(DomainName("*.dev.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Route("127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := wild.Route("127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if got := r.Resolve("dev.acme.com"); got == nil || !got.Equal(web.IP) {
		t.Errorf("dev.acme.com resolves to %v, the app has %v", got, web.IP)
	}
	if got := r.Resolve("tenant.dev.acme.com"); got == nil || !got.Equal(web.IP) {
		t.Errorf("a tenant under the wildcard resolves to %v", got)
	}
	if got := r.Resolve("deep.tenant.dev.acme.com"); got == nil {
		t.Error("a deeper name under the wildcard resolves too")
	}
	if r.Resolve("acme.com") != nil || r.Resolve("other.com") != nil || r.Resolve("nope.doze") != nil {
		t.Error("names nobody declared do not resolve")
	}
	if r.routeFor("tenant.dev.acme.com:443") != "127.0.0.1:3000" {
		t.Errorf("the front door routes the tenant: %q", r.routeFor("tenant.dev.acme.com:443"))
	}
	if !r.IsDomain("dev.acme.com") || !r.IsDomain("x.dev.acme.com:80") || r.IsDomain("web.shop.doze") || r.IsDomain("other.com") {
		t.Error("IsDomain is true for declared domains only")
	}
	if d := r.Domains(); len(d) != 2 || d[0] != "*.dev.acme.com" || d[1] != "dev.acme.com" {
		t.Errorf("Domains = %v", d)
	}
	// Out of the zone and not declared: forwarded, with NXDOMAIN to fall back on.
	resp, fwd := answer(query("other.com", typeA), r.Resolve)
	if !fwd || rcodeOf(resp) != 3 {
		t.Errorf("an unknown domain is forwarded: fwd=%v rcode=%d", fwd, rcodeOf(resp))
	}
	if resp, fwd := answer(query("tenant.dev.acme.com", typeA), r.Resolve); fwd || ancountOf(resp) != 1 {
		t.Errorf("a declared domain is answered here: fwd=%v answers=%d", fwd, ancountOf(resp))
	}
	// Released like any lease; the daemon releases them with the app's.
	_ = dom.Release()
	_ = wild.Release()
	if r.Resolve("dev.acme.com") != nil || r.Resolve("tenant.dev.acme.com") != nil {
		t.Error("a released domain still resolves")
	}
}

func TestTheCAMintsAndRemembersLeafCertificates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, caKeyName)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the key is private to its owner: %v %v", st, err)
	}
	again, err := LoadOrCreateCA(dir)
	if err != nil || again.Fingerprint() != ca.Fingerprint() {
		t.Fatal("a second load is the same authority")
	}
	leaf, err := ca.Leaf("*.dev.acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.Leaf.VerifyHostname("tenant.dev.acme.com"); err != nil {
		t.Errorf("the wildcard certificate covers a tenant: %v", err)
	}
	if err := leaf.Leaf.VerifyHostname("dev.acme.com"); err != nil {
		t.Errorf("and the name under it: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "a.dev.acme.com"}); err != nil {
		t.Errorf("the leaf chains to the root: %v", err)
	}
	if leaf.Leaf.NotAfter.After(time.Now().Add(leafLife + time.Hour)) {
		t.Error("leaf certificates are short-lived")
	}
	// From disk on a fresh load, not minted again.
	fresh, _ := LoadOrCreateCA(dir)
	leaf2, err := fresh.Leaf("*.dev.acme.com")
	if err != nil || leaf2.Leaf.SerialNumber.Cmp(leaf.Leaf.SerialNumber) != 0 {
		t.Error("the leaf comes back from the certs folder")
	}
	// The handshake gets the owner's certificate, and nothing for a stranger.
	r := Open(t.TempDir(), "doze")
	web, _ := r.Claim(Qualified("web", "shop"))
	t.Cleanup(func() { _ = web.Release() })
	if _, err := web.Twin(DomainName("*.dev.acme.com")); err != nil {
		t.Fatal(err)
	}
	get := r.GetCertificate(ca)
	if crt, err := get(&tls.ClientHelloInfo{ServerName: "tenant.dev.acme.com"}); err != nil || crt.Leaf.VerifyHostname("tenant.dev.acme.com") != nil {
		t.Errorf("handshake for a tenant: %v", err)
	}
	if _, err := get(&tls.ClientHelloInfo{ServerName: "other.com"}); err == nil {
		t.Error("a stranger gets no certificate")
	}
	// Rotation: a new root, the old leaves gone.
	old := ca.Fingerprint()
	if err := ca.Rotate(); err != nil {
		t.Fatal(err)
	}
	if ca.Fingerprint() == old {
		t.Error("rotate made no new root")
	}
	if l, err := ca.Leaf("*.dev.acme.com"); err != nil || l.Leaf.CheckSignatureFrom(ca.cert) != nil {
		t.Error("leaves are minted from the new root")
	}
}

func TestUpstreamsSkipLoopbackStubs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	_ = os.WriteFile(path, []byte("nameserver 127.0.0.53\nnameserver 1.1.1.1\nsearch lan\nnameserver 8.8.8.8\n"), 0o644)
	got := resolvConfServers(path)
	if len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "8.8.8.8:53" {
		t.Errorf("resolvConfServers = %v", got)
	}
	if net.ParseIP(resolverIP) == nil || !own(resolverIP) {
		t.Error("our own resolver address is never an upstream")
	}
}

func TestRoutesRememberWhoAskedAndGoStaleWithTheConfig(t *testing.T) {
	home := t.TempDir()
	shop := filepath.Join(t.TempDir(), "shop")
	other := filepath.Join(t.TempDir(), "other")
	for _, d := range []string{shop, other} {
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "doze.hcl"), []byte("stack = \"x\"\n"), 0o644)
	}
	if err := RecordDomains(home, shop, []string{"dev.acme.com", "*.dev.acme.com"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordDomains(home, other, []string{"dev.acme.com", "api.other.com"}); err != nil {
		t.Fatal(err)
	}
	if got := RecordedRoutes(home); len(got) != 2 || got[0] != "api.other.com" || got[1] != "dev.acme.com" {
		t.Fatalf("RecordedRoutes = %v", got)
	}
	// shop drops its domain: other still declares dev.acme.com, so only a
	// route nobody declares could be stale, and none is routed on this
	// machine anyway (no privilege ran).
	_ = RecordDomains(home, shop, nil)
	if rs := readRoutes(home); len(rs["dev.acme.com"]) != 1 || rs["dev.acme.com"][0] != other {
		t.Fatalf("after shop dropped it: %v", rs["dev.acme.com"])
	}
	// other's folder disappears: nothing declares either domain now.
	_ = os.RemoveAll(other)
	if rs := readRoutes(home); len(rs["api.other.com"]) != 1 {
		t.Fatal("the record keeps the folder until it is looked at")
	}
	stale := StaleRoutes(home)
	if len(stale) != 0 {
		t.Fatalf("nothing is routed on this machine, so nothing is stale: %v", stale)
	}
	// Forgetting a project and the record of a removed route.
	_ = ForgetProject(home, shop)
	_ = RouteRemoved(home, "api.other.com")
	if rs := readRoutes(home); len(rs["dev.acme.com"]) != 1 {
		t.Fatalf("a route with a dead claimant is kept for StaleRoutes: %v", rs)
	}
	if _, ok := readRoutes(home)["api.other.com"]; ok {
		t.Error("RouteRemoved forgets a route with no claimant")
	}
	if st := TrustStatus(TrustRequest{Prune: []string{"old.acme.com"}}); len(st) != 1 || st[0].Done || !strings.Contains(st[0].Detail, "no stack declares") {
		t.Errorf("a stale route is a step of its own: %+v", st)
	}
}

func TestAPersonsOwnCertificateIsServedAndChecked(t *testing.T) {
	ca, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	// Stand in for a file the person brought: a leaf from a different CA.
	other, _ := LoadOrCreateCA(filepath.Join(t.TempDir(), "other"))
	if _, err := other.Leaf("api.acme.com"); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(other.dir, caCertsDir, "api.acme.com.crt")
	keyFile := filepath.Join(other.dir, caCertsDir, "api.acme.com.key")
	if exp, err := CheckCertificate(certFile, keyFile, "api.acme.com"); err != nil || exp.Before(time.Now()) {
		t.Fatalf("a good file is accepted: %v", err)
	}
	if _, err := CheckCertificate(certFile, keyFile, "www.acme.com"); err == nil {
		t.Error("a file that does not cover the name is refused")
	}
	if _, err := CheckCertificate(certFile, keyFile, "*.acme.com"); err == nil {
		t.Error("a single-name file does not cover a wildcard")
	}
	r := Open(t.TempDir(), "doze")
	web, _ := r.Claim(Qualified("api", "shop"))
	t.Cleanup(func() { _ = web.Release() })
	dom, err := web.Twin(DomainName("api.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Certificate(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	crt, err := r.GetCertificate(ca)(&tls.ClientHelloInfo{ServerName: "api.acme.com"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(crt.Certificate[0])
	if leaf.CheckSignatureFrom(other.cert) != nil || leaf.CheckSignatureFrom(ca.cert) == nil {
		t.Error("the handshake serves the person's file, not a minted one")
	}
	// Without an authority, a domain with files still serves.
	if _, err := r.GetCertificate(nil)(&tls.ClientHelloInfo{ServerName: "api.acme.com"}); err != nil {
		t.Errorf("files need no authority: %v", err)
	}
}

func TestTheFrontDoorServesADomainOverTLSAndRedirectsPlainRequests(t *testing.T) {
	reg := Open(t.TempDir(), "doze")
	ca, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "hello from "+r.Host)
	}))
	defer backend.Close()
	web, err := reg.Claim(Qualified("web", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = web.Release() })
	wild, err := web.Twin(DomainName("*.dev.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := wild.Route(backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err := web.Route(backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	// Two free ports on loopback stand in for 80 and 443.
	plain, tlsAddr := freeAddr(t, "tcp4"), freeAddr(t, "tcp4")
	t.Setenv(EnvIngress, plain)
	t.Setenv(EnvIngressTLS, tlsAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	front := ServeFrontDoor(ctx, reg, ca, t.Logf)
	defer front.Close()
	if !front.Bound(ctx) {
		t.Fatal("the plain port was never bound")
	}
	waitFor(t, func() bool { _, ok := reg.IngressTLSHolder(); return ok })

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "tenant.dev.acme.com"},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", tlsAddr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get("https://tenant.dev.acme.com/")
	if err != nil {
		t.Fatalf("https through the front door: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello from tenant.dev.acme.com" {
		t.Errorf("https answer = %d %q", resp.StatusCode, body)
	}
	// Plain http for a domain is sent to https; a doze name stays plain.
	plainClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+plain+"/x?y=1", nil)
	req.Host = "tenant.dev.acme.com"
	r2, err := plainClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusTemporaryRedirect || r2.Header.Get("Location") != "https://tenant.dev.acme.com/x?y=1" {
		t.Errorf("plain request for a domain = %d %q", r2.StatusCode, r2.Header.Get("Location"))
	}
	req3, _ := http.NewRequestWithContext(ctx, "GET", "http://"+plain+"/", nil)
	req3.Host = "web.shop.doze"
	r3, err := plainClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := io.ReadAll(r3.Body)
	_ = r3.Body.Close()
	if r3.StatusCode != 200 || string(b3) != "hello from web.shop.doze" {
		t.Errorf("a doze name over plain http = %d %q", r3.StatusCode, b3)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting")
}

func TestAnUnservedDomainIsForwardedUpstreamAndTheZoneNeverIs(t *testing.T) {
	// A fake upstream that answers every A question with 203.0.113.9.
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	var asked []string
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
			asked = append(asked, name)
			mu.Unlock()
			resp, _ := answer(buf[:n], func(string) net.IP { return net.IPv4(203, 0, 113, 9) })
			_, _ = up.WriteToUDP(resp, addr)
		}
	}()
	old := upstreamAddrs
	upstreamAddrs = func() []string { return []string{up.LocalAddr().String()} }
	t.Cleanup(func() { upstreamAddrs = old })

	r := Open(t.TempDir(), "doze")
	web, _ := r.Claim(Qualified("web", "shop"))
	t.Cleanup(func() { _ = web.Release() })
	if _, err := web.Twin(DomainName("dev.acme.com")); err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t, "udp4")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := ServeAt(ctx, r, addr, t.Logf)
	defer srv.Close()
	if !srv.Bound(ctx) {
		t.Fatal("resolver never bound")
	}
	ask := func(name string) (net.IP, uint16) {
		c, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(query(name, typeA))
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp := buf[:n]
		if ancountOf(resp) == 0 {
			return nil, rcodeOf(resp)
		}
		return net.IPv4(resp[n-4], resp[n-3], resp[n-2], resp[n-1]), rcodeOf(resp)
	}
	// A declared domain is answered here; the upstream is not asked.
	if ip, _ := ask("dev.acme.com"); ip == nil || !ip.Equal(web.IP) {
		t.Errorf("dev.acme.com = %v, want the app's %v", ip, web.IP)
	}
	// A domain nobody declares (the stack went down) comes from upstream.
	if ip, _ := ask("dev.other.com"); ip == nil || !ip.Equal(net.IPv4(203, 0, 113, 9)) {
		t.Errorf("dev.other.com = %v, want the upstream's answer", ip)
	}
	// The zone is never forwarded: a typo is NXDOMAIN here.
	if _, rcode := ask("nope.shop.doze"); rcode != 3 {
		t.Errorf("nope.shop.doze rcode = %d, want NXDOMAIN", rcode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || asked[0] != "dev.other.com" {
		t.Errorf("upstream was asked %v, want only dev.other.com", asked)
	}
}

func TestValidDomainRefusesWhatAShellOrAPathCouldMisread(t *testing.T) {
	for _, bad := range []string{"dev.acme.com;rm", "dev.acme.com'x", "dev.acme.com$(id)", "../etc", "dev/acme.com", "dev.acme.com\n", "dev acme.com", "dev.acme.com\\x", "*.acme.com/x", "dev..acme.com", ".acme.com"} {
		if err := ValidDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAWildcardOwnsTheNameUnderItAndOneLevelBelow(t *testing.T) {
	r := Open(t.TempDir(), "doze")
	web, _ := r.Claim(Qualified("web", "shop"))
	t.Cleanup(func() { _ = web.Release() })
	if _, err := web.Twin(DomainName("*.dev.acme.com")); err != nil {
		t.Fatal(err)
	}
	m := r.Snapshot()
	for _, h := range []string{"dev.acme.com", "tenant.dev.acme.com", "a.b.dev.acme.com"} {
		if _, owner, ok := lookupDomain(m, h); !ok || owner != "*.dev.acme.com" {
			t.Errorf("%s: owner %q ok=%v", h, owner, ok)
		}
	}
	if _, _, ok := lookupDomain(m, "acme.com"); ok {
		t.Error("the parent of a wildcard is not owned")
	}
	ca, _ := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"))
	get := r.GetCertificate(ca)
	crt, err := get(&tls.ClientHelloInfo{ServerName: "dev.acme.com"})
	if err != nil || crt.Leaf.VerifyHostname("dev.acme.com") != nil {
		t.Errorf("the name under a wildcard is served and covered: %v", err)
	}
	if crt.Leaf.VerifyHostname("a.b.dev.acme.com") == nil {
		t.Error("a certificate covers one level only; a deeper name is documented, not served")
	}
	// A peer that is not this machine gets no certificate.
	lan, _ := net.ResolveTCPAddr("tcp", "192.168.1.50:5555")
	if _, err := get(&tls.ClientHelloInfo{ServerName: "dev.acme.com", Conn: fakeConn{lan}}); err == nil {
		t.Error("a LAN peer was served a certificate")
	}
}

type fakeConn struct{ remote net.Addr }

func (c fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c fakeConn) Close() error                     { return nil }
func (c fakeConn) LocalAddr() net.Addr              { return c.remote }
func (c fakeConn) RemoteAddr() net.Addr             { return c.remote }
func (c fakeConn) SetDeadline(time.Time) error      { return nil }
func (c fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c fakeConn) SetWriteDeadline(time.Time) error { return nil }

func TestADroppedDomainIsStaleWhileItsRouteRemainsAndForgottenWhenItGoes(t *testing.T) {
	home := t.TempDir()
	shop := filepath.Join(t.TempDir(), "shop")
	_ = os.MkdirAll(shop, 0o755)
	_ = os.WriteFile(filepath.Join(shop, "doze.hcl"), []byte("stack = \"x\"\n"), 0o644)
	routed := map[string]bool{"dev.acme.com": true}
	old := routedCheck
	routedCheck = func(d string) bool { return routed[d] }
	t.Cleanup(func() { routedCheck = old })

	_ = RecordDomains(home, shop, []string{"dev.acme.com", "*.dev.acme.com"})
	if s := StaleRoutes(home); len(s) != 0 {
		t.Fatalf("declared and routed is not stale: %v", s)
	}
	// Dropped from the config while the machine still routes it: stale.
	_ = RecordDomains(home, shop, nil)
	if s := StaleRoutes(home); len(s) != 1 || s[0] != "dev.acme.com" {
		t.Fatalf("stale = %v", s)
	}
	// A request to trust something else prunes it; once the route is gone
	// the record forgets it.
	req := TrustRequest{Domains: []string{"api.acme.com"}, Home: home, Prune: StaleRoutes(home)}
	if set := req.routeSet(); len(set) != 1 || set[0] != "api.acme.com" {
		t.Errorf("routeSet = %v, want only the new domain", set)
	}
	routed["dev.acme.com"] = false
	_ = RouteRemoved(home, "dev.acme.com")
	if _, ok := readRoutes(home)["dev.acme.com"]; ok {
		t.Error("a removed route is forgotten")
	}
	// A crafted key in the file never reaches a script.
	_ = os.WriteFile(routesPath(home), []byte(`{"dev.acme.com; rm -rf /": ["`+shop+`"], "ok.acme.com": ["`+shop+`"]}`), 0o644)
	if got := RecordedRoutes(home); len(got) != 1 || got[0] != "ok.acme.com" {
		t.Errorf("RecordedRoutes = %v", got)
	}
}
