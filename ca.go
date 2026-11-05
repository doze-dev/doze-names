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
}

// CADir is where the authority lives under a doze home.
func CADir(home string) string { return filepath.Join(home, caDirName) }

// RootPath is the authority's certificate, PEM, for trusting and for
// SSL_CERT_FILE and the like.
func (c *CA) RootPath() string { return filepath.Join(c.dir, caCertName) }

// LoadOrCreateCA opens the authority under dir, making it when there is
// none. The key file is readable by its owner only.
func LoadOrCreateCA(dir string) (*CA, error) {
	c := &CA{dir: dir, leafs: map[string]*tls.Certificate{}}
	certPEM, err1 := os.ReadFile(filepath.Join(dir, caCertName))
	keyPEM, err2 := os.ReadFile(filepath.Join(dir, caKeyName))
	if err1 == nil && err2 == nil {
		if err := c.load(certPEM, keyPEM); err == nil && time.Now().Before(c.cert.NotAfter.Add(-leafLife)) {
			return c, nil
		}
	}
	if err := c.create(); err != nil {
		return nil, err
	}
	return c, nil
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
// is dropped. The new root needs trusting again.
func (c *CA) Rotate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leafs = map[string]*tls.Certificate{}
	return c.create()
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
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			return nil, errors.New("doze: no server name in the handshake")
		}
		m := r.Snapshot()
		e, ok := lookupDomain(m, hello.ServerName)
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
		if ca == nil {
			return nil, fmt.Errorf("doze: no certificate for %s: no authority and no files", hello.ServerName)
		}
		return ca.Leaf(ownerOf(m, hello.ServerName))
	}
}

// ownerOf is the registered domain (exact or wildcard) that owns host.
func ownerOf(m map[string]Entry, host string) string {
	h := normalize(host)
	if e, ok := m[h]; ok && e.Tier == TierDomain {
		return h
	}
	for {
		_, rest, found := strings.Cut(h, ".")
		if !found || !strings.Contains(rest, ".") {
			return normalize(host)
		}
		if e, ok := m["*."+rest]; ok && e.Tier == TierDomain {
			return "*." + rest
		}
		h = rest
	}
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

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
