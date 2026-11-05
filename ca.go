package names

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The doze certificate authority: one per machine, under <home>/ca, made
// the first time a domain needs https and trusted once by the person
// (trust_*.go). The front door mints a short-lived certificate per domain
// from it on the first TLS handshake that asks, and keeps them beside it.
// The key never leaves the folder; a copy of it lets whoever has it forge
// only this machine's own names, which is the risk mkcert and OrbStack take
// too. Rotate makes a new one; trusting it again is one prompt.

const (
	caDirName    = "ca"
	caCertName   = "root.crt"
	caKeyName    = "root.key"
	caCertsDir   = "certs"
	caLife       = 10 * 365 * 24 * time.Hour
	leafLife     = 30 * 24 * time.Hour
	leafRenewAt  = 7 * 24 * time.Hour
	caCommonName = "doze local CA"
)

// CA is the machine's authority, loaded or made.
type CA struct {
	dir  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu    sync.Mutex
	leafs map[string]*tls.Certificate // by the domain entry they were minted for
	// previous are the fingerprints of roots rotated out that may still be
	// trusted on the machine, until a prompt removes them.
	previous []string
}

// CADir is where the authority lives under a doze home.
func CADir(home string) string { return filepath.Join(home, caDirName) }

// RootPath is the authority's certificate, PEM, for trusting and for
// SSL_CERT_FILE and the like.
func (c *CA) RootPath() string { return filepath.Join(c.dir, caCertName) }

// LoadOrCreateCA opens the authority under dir, making it when there is
// none. The key file is readable by its owner only. Two daemons starting
// together on a fresh home make one authority between them: creation is
// under a lock, and the loser loads what the winner wrote. A file that is
// there but cannot be read is an error, never silently replaced: the
// keychain may trust it.
func LoadOrCreateCA(dir string) (*CA, error) {
	if c, ok, err := openCA(dir); ok || err != nil {
		return c, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	unlock, err := lockFile(lock)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if c, ok, err := openCA(dir); ok || err != nil {
		return c, err // the other daemon got here first
	}
	c := &CA{dir: dir, leafs: map[string]*tls.Certificate{}}
	if err := c.create(); err != nil {
		return nil, err
	}
	return c, nil
}

// openCA loads the authority: ok is false when there is none, err says one
// is there and unreadable, or expiring within a leaf's life.
func openCA(dir string) (*CA, bool, error) {
	c := &CA{dir: dir, leafs: map[string]*tls.Certificate{}}
	certPEM, err1 := os.ReadFile(filepath.Join(dir, caCertName))
	keyPEM, err2 := os.ReadFile(filepath.Join(dir, caKeyName))
	if os.IsNotExist(err1) && os.IsNotExist(err2) {
		return nil, false, nil
	}
	if err1 != nil {
		return nil, false, err1
	}
	if err2 != nil {
		return nil, false, err2
	}
	if err := c.load(certPEM, keyPEM); err != nil {
		return nil, false, fmt.Errorf("%s: %w (doze trust --rotate makes a new authority)", dir, err)
	}
	if !time.Now().Before(c.cert.NotAfter.Add(-leafLife)) {
		return nil, false, fmt.Errorf("the authority in %s expires on %s: doze trust --rotate makes a new one", dir, c.cert.NotAfter.Format("2006-01-02"))
	}
	c.previous = readPrevious(dir)
	return c, true, nil
}

func (c *CA) load(certPEM, keyPEM []byte) error {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return errors.New("ca: not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return err
	}
	c.cert, c.key = cert, key
	return nil
}

func (c *CA) create() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	host = strings.TrimSuffix(host, ".local")
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s · %s · %s", caCommonName, host, now.Format("2006-01-02")),
			Organization: []string{"doze"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLife),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(c.dir, caCertsDir), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(c.dir, caKeyName), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(c.dir, caCertName), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	c.cert, c.key = cert, key
	// Leaf certificates of an older authority are no good now.
	entries, _ := os.ReadDir(filepath.Join(c.dir, caCertsDir))
	for _, e := range entries {
		_ = os.Remove(filepath.Join(c.dir, caCertsDir, e.Name()))
	}
	return nil
}

// Rotate replaces the authority with a new one; everything minted before
// is dropped. The new root needs trusting again; the old root is kept
// under previous/ with its fingerprint remembered, so the same prompt can
// stop trusting it, by file (the admin trust store wants the certificate)
// or by fingerprint.
func (c *CA) Rotate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.Fingerprint()
	c.keepPrevious(old, c.cert.Raw)
	c.leafs = map[string]*tls.Certificate{}
	if err := c.create(); err != nil {
		return err
	}
	c.previous = appendUnique(c.previous, old)
	return writePrevious(c.dir, c.previous)
}

// RotateCA makes a new authority under dir whatever state the old one is
// in: a root that cannot be read, or has expired, is exactly what rotation
// is for, so this does not refuse what LoadOrCreateCA refuses. What can be
// learned of the old root (its fingerprint from the file, or the doze roots
// the machine trusts) is remembered so the trust prompt removes it.
func RotateCA(dir string) (*CA, error) {
	if c, ok, err := openCA(dir); ok && err == nil {
		return c, c.Rotate()
	}
	c := &CA{dir: dir, leafs: map[string]*tls.Certificate{}, previous: readPrevious(dir)}
	if raw, err := os.ReadFile(filepath.Join(dir, caCertName)); err == nil {
		if b, _ := pem.Decode(raw); b != nil {
			if old, err := x509.ParseCertificate(b.Bytes); err == nil {
				sum := sha256.Sum256(old.Raw)
				fp := hex.EncodeToString(sum[:])
				c.keepPrevious(fp, old.Raw)
				c.previous = appendUnique(c.previous, fp)
			}
		}
	}
	for _, fp := range trustedDozeRoots() {
		c.previous = appendUnique(c.previous, fp)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := c.create(); err != nil {
		return nil, err
	}
	return c, writePrevious(dir, c.previous)
}

// keepPrevious files a rotated-out root by its fingerprint.
func (c *CA) keepPrevious(fp string, raw []byte) {
	_ = os.MkdirAll(filepath.Join(c.dir, previousDir), 0o700)
	_ = writeFileAtomic(c.previousPath(fp), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0o644)
}

// previousPath is where a rotated-out root is kept, if it was.
func (c *CA) previousPath(fp string) string {
	return filepath.Join(c.dir, previousDir, fp+".crt")
}

func appendUnique(fps []string, fp string) []string {
	for _, have := range fps {
		if have == fp {
			return fps
		}
	}
	return append(fps, fp)
}

// Previous are the fingerprints of rotated-out roots not yet untrusted.
func (c *CA) Previous() []string { return append([]string(nil), c.previous...) }

// forgetUntrustedPrevious drops the rotated-out roots the machine no longer
// trusts, and their files.
func (c *CA) forgetUntrustedPrevious() error {
	var keep []string
	for _, fp := range c.previous {
		if trusted, _ := fingerprintTrusted(c, fp); trusted {
			keep = append(keep, fp)
		} else {
			_ = os.Remove(c.previousPath(fp))
		}
	}
	c.previous = keep
	return writePrevious(c.dir, keep)
}

const (
	previousName = "previous.json"
	previousDir  = "previous"
)

// readPrevious reads the rotated-out fingerprints. The file is the person's
// to edit and its entries reach a privileged script and a keychain lookup,
// so only a SHA-256 in hex gets through.
func readPrevious(dir string) []string {
	var raw, out []string
	if b, err := os.ReadFile(filepath.Join(dir, previousName)); err == nil {
		_ = json.Unmarshal(b, &raw)
	}
	for _, fp := range raw {
		if validFingerprint(fp) {
			out = append(out, strings.ToLower(fp))
		}
	}
	return out
}

func validFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	_, err := hex.DecodeString(fp)
	return err == nil
}

// shortFP is a fingerprint's first twelve characters, for a line of status.
func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}

func writePrevious(dir string, fps []string) error {
	if len(fps) == 0 {
		err := os.Remove(filepath.Join(dir, previousName))
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	b, _ := json.Marshal(fps)
	return writeFileAtomic(filepath.Join(dir, previousName), b, 0o644)
}

// Subject is the root's common name, which is how the keychain lists it.
func (c *CA) Subject() string { return c.cert.Subject.CommonName }

// NotAfter is when the root expires.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Fingerprint is the root's SHA-256, hex, for the keychain commands and
// doctor.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// GetCertificate is for tls.Config: the certificate for the name the client
// asked for, minted on first use from the domain entry that owns it. A name
// nobody registered gets no certificate, so the handshake fails rather than
// answering for a stranger.
func (r *Registry) GetCertificate(ca *CA) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.getCertificate(func() *CA { return ca })
}

// getCertificate is GetCertificate over an authority looked up per
// handshake, so the holder of the https port serves from whatever root is
// on disk now: one made after it started, or one rotated in since.
func (r *Registry) getCertificate(source func() *CA) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			return nil, errors.New("doze: no server name in the handshake")
		}
		// Only this machine is answered, as on the plain port: a LAN peer
		// learns nothing about what is served here.
		if hello.Conn != nil && !fromThisMachine(hello.Conn.RemoteAddr().String()) {
			return nil, errors.New("doze names are served to this machine only")
		}
		m := r.Snapshot()
		e, owner, ok := lookupDomain(m, hello.ServerName)
		if !ok {
			return nil, fmt.Errorf("doze: %s is not a domain this machine serves", hello.ServerName)
		}
		if e.Cert != "" {
			// The person's own certificate, as the files are now.
			crt, err := tls.LoadX509KeyPair(e.Cert, e.Key)
			if err != nil {
				return nil, fmt.Errorf("doze: %s: %w", e.Cert, err)
			}
			return &crt, nil
		}
		ca := source()
		if ca == nil {
			return nil, fmt.Errorf("doze: no certificate for %s: no authority and no files", hello.ServerName)
		}
		return ca.Leaf(owner)
	}
}

// The authority as it is on disk now, for a process that serves https for
// as long as it runs: another process makes or rotates the root, and this
// one must follow without restarting. The root file is checked at most
// every currentCAEvery and reloaded when it changed; leafs minted from the
// old root go with it.
type caCache struct {
	mu   sync.Mutex
	at   time.Time
	id   string // mtime and size of the root file when loaded
	ca   *CA
	err  error
	dirs map[string]*caCache
}

var current = &caCache{dirs: map[string]*caCache{}}

var currentCAEvery = 2 * time.Second

// CurrentCA opens the authority under dir, reloading it when the root
// file changed since. nil with no error means there is none yet.
func CurrentCA(dir string) (*CA, error) {
	current.mu.Lock()
	c, ok := current.dirs[dir]
	if !ok {
		c = &caCache{}
		current.dirs[dir] = c
	}
	current.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) < currentCAEvery {
		return c.ca, c.err
	}
	c.at = time.Now()
	id := ""
	if st, err := os.Stat(filepath.Join(dir, caCertName)); err == nil {
		id = fmt.Sprintf("%d:%d", st.ModTime().UnixNano(), st.Size())
	}
	if id == c.id && (c.ca != nil || c.err != nil) {
		return c.ca, c.err
	}
	c.id = id
	c.ca, c.err = ProbeCA(dir)
	return c.ca, c.err
}

// ProbeCA opens the authority under dir without making one: nil and no
// error when there is none; an error when one is there and cannot be used
// (unreadable, or expiring), which doze trust --rotate fixes.
func ProbeCA(dir string) (*CA, error) {
	c, ok, err := openCA(dir)
	if !ok {
		return nil, err
	}
	return c, nil
}

// Leaf is the certificate for a registered domain: from memory, from the
// certs folder, or minted now. A wildcard's certificate carries the
// wildcard and the name under it.
func (c *CA) Leaf(domain string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if crt, ok := c.leafs[domain]; ok && leafFresh(crt) {
		return crt, nil
	}
	base := filepath.Join(c.dir, caCertsDir, strings.ReplaceAll(domain, "*", "_wildcard"))
	if crt, err := tls.LoadX509KeyPair(base+".crt", base+".key"); err == nil {
		if crt.Leaf, err = x509.ParseCertificate(crt.Certificate[0]); err == nil && leafFresh(&crt) && crt.Leaf.CheckSignatureFrom(c.cert) == nil {
			c.leafs[domain] = &crt
			return &crt, nil
		}
	}
	crt, err := c.mint(domain, base)
	if err != nil {
		return nil, err
	}
	c.leafs[domain] = crt
	return crt, nil
}

func leafFresh(crt *tls.Certificate) bool {
	return crt != nil && crt.Leaf != nil && time.Now().Before(crt.Leaf.NotAfter.Add(-leafRenewAt))
}

func (c *CA) mint(domain, base string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	now := time.Now()
	names := []string{domain}
	if Wildcard(domain) {
		names = append(names, RouteDomain(domain))
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: RouteDomain(domain), Organization: []string{"doze"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		return nil, err
	}
	_ = writeFileAtomic(base+".key", keyPEM, 0o600)
	_ = writeFileAtomic(base+".crt", certPEM, 0o644)
	crt, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	crt.Leaf, _ = x509.ParseCertificate(der)
	return &crt, nil
}

// writeFileAtomic writes beside the file and renames into place. The
// temporary name is this process's own, so two processes writing the same
// file at once (two daemons starting together) never rename each other's
// half-written copy into place.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp.%d.%d", path, os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// OpenCA opens the authority under dir without making one: for a surface
// that only reports on it. ok is false when there is none, or it cannot be
// read.
func OpenCA(dir string) (*CA, bool) {
	c, ok, err := openCA(dir)
	return c, ok && err == nil
}

// bundleName is the file clients that replace their trust store are
// pointed at: the system's roots and the doze root together.
const bundleName = "bundle.pem"

// Bundle writes <dir>/bundle.pem and returns its path: the roots this
// machine trusts, whatever the SSL_CERT_FILE this process inherited holds
// (a corporate bundle, say), and the doze root. SSL_CERT_FILE and
// REQUESTS_CA_BUNDLE replace a client's store rather than add to it, so
// pointing them at the root alone would cut the stack off from every
// public https host; this keeps them whole. An inherited SSL_CERT_FILE that
// is this bundle itself (a shell that ran eval "$(doze env)") is not folded
// in, and no doze root but the current one is carried: a rotated-out root
// never rides along. Written under the authority's lock, so two daemons
// starting together do not race on it.
func (c *CA) Bundle() (string, error) {
	lock, err := os.OpenFile(filepath.Join(c.dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	unlock, err := lockFile(lock)
	if err != nil {
		return "", err
	}
	defer unlock()
	root, err := os.ReadFile(c.RootPath())
	if err != nil {
		return "", err
	}
	var b []byte
	b = append(b, withoutDozeRoots(systemRootsPEM())...)
	if f := os.Getenv("SSL_CERT_FILE"); f != "" && !sameFile(f, c.BundlePath()) {
		if extra, err := os.ReadFile(f); err == nil {
			b = append(b, '\n')
			b = append(b, withoutDozeRoots(extra)...)
		}
	}
	b = append(b, '\n')
	b = append(b, root...)
	path := c.BundlePath()
	if err := writeFileAtomic(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// BundlePath is where Bundle writes.
func (c *CA) BundlePath() string { return filepath.Join(c.dir, bundleName) }

// EnsureBundle is Bundle unless a bundle at least as new as the root is
// there already: for a surface run often (doze env in a shell hook) that
// must point at a bundle but need not rewrite it each time.
func (c *CA) EnsureBundle() (string, error) {
	b, err1 := os.Stat(c.BundlePath())
	r, err2 := os.Stat(c.RootPath())
	if err1 == nil && err2 == nil && !b.ModTime().Before(r.ModTime()) && b.Size() > 0 {
		return c.BundlePath(), nil
	}
	return c.Bundle()
}

func sameFile(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

// withoutDozeRoots drops every doze authority from a PEM bundle, current
// or rotated out, keeping everything else as it was.
func withoutDozeRoots(pemBytes []byte) []byte {
	var out []byte
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type == "CERTIFICATE" {
			if crt, err := x509.ParseCertificate(block.Bytes); err == nil && strings.HasPrefix(crt.Subject.CommonName, caCommonName) {
				continue
			}
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
}

// systemRootsPEM is the machine's trusted roots as PEM: Apple's curated
// file of the system roots on macOS plus any authority an administrator
// trusted (trust_darwin.go), the distribution's bundle on Linux.
func systemRootsPEM() []byte {
	if b := platformRootsPEM(); len(b) > 0 {
		return b
	}
	for _, p := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem"} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	return nil
}
