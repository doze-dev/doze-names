package names

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
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
