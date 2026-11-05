package names

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
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

// A stack that brings its own certificate files gets https from the front
// door with no authority on the machine at all: the port is served
// whenever names are, and the files are what the handshake offers.
func TestTheFrontDoorServesAPersonsOwnFilesWithoutAnAuthority(t *testing.T) {
	other, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Leaf("api.acme.com"); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(other.dir, caCertsDir, "api.acme.com.crt")
	keyFile := filepath.Join(other.dir, caCertsDir, "api.acme.com.key")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "own files for "+r.Host)
	}))
	defer backend.Close()
	reg := Open(t.TempDir(), "doze")
	web, err := reg.Claim(Qualified("api", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = web.Release() })
	dom, err := web.Twin(DomainName("api.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Certificate(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if err := dom.Route(backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	plain, tlsAddr := freeAddr(t, "tcp4"), freeAddr(t, "tcp4")
	t.Setenv(EnvIngress, plain)
	t.Setenv(EnvIngressTLS, tlsAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	noCA := filepath.Join(t.TempDir(), "ca") // never made
	front := ServeFrontDoor(ctx, reg, noCA, t.Logf)
	defer front.Close()
	waitFor(t, func() bool { _, ok := reg.IngressTLSHolder(); return ok })

	body, err := httpsGet(ctx, tlsAddr, "api.acme.com", other.cert)
	if err != nil {
		t.Fatalf("https with the person's files: %v", err)
	}
	if body != "own files for api.acme.com" {
		t.Errorf("body = %q", body)
	}
	if _, err := os.Stat(filepath.Join(noCA, caCertName)); err == nil {
		t.Error("serving the person's files must not make an authority")
	}
}

// httpsGet fetches https://<host>/ through the TLS front door at addr,
// trusting root alone.
func httpsGet(ctx context.Context, addr, host string, root *x509.Certificate) (string, error) {
	pool := x509.NewCertPool()
	if root != nil {
		pool.AddCert(root)
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String(), nil
}

// The process holding the https port follows the authority on disk: one
// made after it started, and one rotated in by doze trust --rotate, so a
// rotation reaches browsers without restarting the stack.
func TestARotatedAuthorityIsSeenByTheRunningFrontDoor(t *testing.T) {
	old := currentCAEvery
	currentCAEvery = 0
	t.Cleanup(func() { currentCAEvery = old })

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()
	reg := Open(t.TempDir(), "doze")
	web, err := reg.Claim(Qualified("web", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = web.Release() })
	dom, err := web.Twin(DomainName("dev.acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Route(backend.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	plain, tlsAddr := freeAddr(t, "tcp4"), freeAddr(t, "tcp4")
	t.Setenv(EnvIngress, plain)
	t.Setenv(EnvIngressTLS, tlsAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	caDir := filepath.Join(t.TempDir(), "ca")
	front := ServeFrontDoor(ctx, reg, caDir, t.Logf) // before any authority exists
	defer front.Close()
	waitFor(t, func() bool { _, ok := reg.IngressTLSHolder(); return ok })

	// No authority yet: a minted domain has nothing to offer.
	if _, err := httpsGet(ctx, tlsAddr, "dev.acme.com", nil); err == nil {
		t.Fatal("without an authority or files the handshake must fail")
	}
	// Another process (the declaring daemon) makes it; the holder follows.
	first, err := LoadOrCreateCA(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := httpsGet(ctx, tlsAddr, "dev.acme.com", first.cert); err != nil {
		t.Fatalf("after the authority was made: %v", err)
	}
	// doze trust --rotate in yet another process.
	time.Sleep(20 * time.Millisecond) // a distinct mtime for the root file
	second, err := RotateCA(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := httpsGet(ctx, tlsAddr, "dev.acme.com", second.cert); err != nil {
		t.Fatalf("after rotation the new root signs: %v", err)
	}
	if _, err := httpsGet(ctx, tlsAddr, "dev.acme.com", first.cert); err == nil {
		t.Error("after rotation the old root must not verify what is served")
	}
	if p := second.Previous(); len(p) != 1 || p[0] != first.Fingerprint() {
		t.Errorf("previous = %v, want the first root's fingerprint", p)
	}
	if _, err := os.Stat(second.previousPath(first.Fingerprint())); err != nil {
		t.Error("the rotated-out root is kept by file, for the admin trust store's removal")
	}
}

// Rotation is the remedy for a root that cannot be used, so it must work
// on one; and the file of rotated-out fingerprints is a person's to edit,
// so what it holds is checked before it reaches a script.
func TestRotateCAWorksOnABrokenRootAndPreviousIsChecked(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	oldFP := ca.Fingerprint()
	if err := os.WriteFile(filepath.Join(dir, caKeyName), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeCA(dir); err == nil {
		t.Fatal("a broken key must be an error to every reporting surface")
	}
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("a broken key must never be silently replaced")
	}
	fresh, err := RotateCA(dir)
	if err != nil {
		t.Fatalf("rotation on a broken root: %v", err)
	}
	if fresh.Fingerprint() == oldFP {
		t.Error("rotation made no new root")
	}
	if p := fresh.Previous(); len(p) != 1 || p[0] != oldFP {
		t.Errorf("the old root's fingerprint is remembered from its file: %v", p)
	}
	if _, err := ProbeCA(dir); err != nil {
		t.Errorf("after rotation the authority is usable: %v", err)
	}
	// Short, empty or non-hex entries never reach a script or a slice.
	if err := os.WriteFile(filepath.Join(dir, previousName), []byte(`["", "abc", "zz", "`+oldFP+`"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readPrevious(dir); len(got) != 1 || got[0] != oldFP {
		t.Errorf("readPrevious = %v, want only the valid fingerprint", got)
	}
	again, err := ProbeCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range TrustStatus(TrustRequest{CA: again}) {
		_ = st // must not panic on any entry
	}
}

// The bundle carries the machine's roots once and the current doze root
// once: a shell that already points SSL_CERT_FILE at the bundle does not
// fold it in again, a rotated-out doze root in an inherited file is
// dropped, and daemons writing it together never leave a torn file.
func TestTheBundleHoldsSystemRootsOnceAndNoOldDozeRoot(t *testing.T) {
	ca, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	stale, _ := LoadOrCreateCA(filepath.Join(t.TempDir(), "stale"))
	corpCert, corpPEM := selfSignedRoot(t, "Corp Root CA") // not a doze root, so it is kept
	stalePEM, _ := os.ReadFile(stale.RootPath())
	inherited := filepath.Join(t.TempDir(), "corp-bundle.pem")
	if err := os.WriteFile(inherited, append(append([]byte{}, corpPEM...), stalePEM...), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", inherited)
	path, err := ca.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	dozeRoots, total := countRoots(t, path)
	if dozeRoots != 1 {
		t.Errorf("bundle holds %d doze roots, want only the current one", dozeRoots)
	}
	if !bundleHas(t, path, corpCert) {
		t.Error("the inherited corporate root is kept")
	}
	if bundleHas(t, path, stale.cert) {
		t.Error("a rotated-out doze root in the inherited file is dropped")
	}
	// A shell that ran eval "$(doze env)" hands the bundle back as
	// SSL_CERT_FILE: the next write must not double it.
	t.Setenv("SSL_CERT_FILE", path)
	if _, err := ca.Bundle(); err != nil {
		t.Fatal(err)
	}
	if d, n := countRoots(t, path); d != 1 || n != total-1 {
		t.Errorf("after folding the bundle into itself: %d doze roots, %d certificates (was %d; the corporate root is gone with its file, nothing else changes)", d, n, total)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ca.Bundle(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if d, _ := countRoots(t, path); d != 1 {
		t.Errorf("after concurrent writes the bundle holds %d doze roots", d)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Error("a fixed temporary name was used")
	}
}

func countRoots(t *testing.T, path string) (doze, total int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return doze, total
		}
		total++
		// A public root with a negative serial is kept as the system shipped it,
		// though Go will not parse it.
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if strings.HasPrefix(crt.Subject.CommonName, caCommonName) {
			doze++
		}
	}
}

func bundleHas(t *testing.T, path string, want *x509.Certificate) bool {
	t.Helper()
	b, _ := os.ReadFile(path)
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return false
		}
		if string(block.Bytes) == string(want.Raw) {
			return true
		}
	}
}

// A relayed answer's TTLs are capped, through compressed names too.
func TestCapTTLWalksEveryRecord(t *testing.T) {
	q := query("dev.acme.com", typeA)
	msg := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(msg[6:8], 2) // two answers
	rr := func(ttl uint32) []byte {
		var b []byte
		b = append(b, 0xC0, 0x0C) // the question's name
		b = binary.BigEndian.AppendUint16(b, typeA)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint16(b, 4)
		return append(b, 203, 0, 113, 9)
	}
	msg = append(msg, rr(3600)...)
	msg = append(msg, rr(5)...)
	out := capTTL(msg, 10)
	n := len(out)
	if got := binary.BigEndian.Uint32(out[n-10:]); got != 5 {
		t.Errorf("a short TTL is left alone, got %d", got)
	}
	if got := binary.BigEndian.Uint32(out[n-16-10:]); got != 10 {
		t.Errorf("a long TTL is capped, got %d", got)
	}
	if string(capTTL(msg[:20], 10)) != string(msg[:20]) {
		t.Error("a truncated message is returned as it was")
	}
}

// selfSignedRoot makes a root certificate with its own name, standing in
// for a corporate authority.
func selfSignedRoot(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := x509.ParseCertificate(der)
	return crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
