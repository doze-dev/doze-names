package names

// The shared registry: ~/.doze/names.json, written by every doze binary and
// read by whichever one is serving the resolver.
//
// Liveness is by PID rather than by clean shutdown, because a crashed process
// cannot run a shutdown hook. Every read prunes entries whose process is gone,
// so the file self-heals and a kill -9 costs nothing.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// FileName is the registry's name inside the doze home.
const FileName = "names.json"

// FormatVersion is the version of the registry file this build reads and
// writes. The file is shared by three programs that are released separately,
// so each write stamps it and each read checks it: a build that meets a file
// from a newer one stops and says so, rather than rewriting names it does not
// understand.
//
// Raise it when an older build could no longer read the file correctly — a
// field changing meaning, an entry it must not prune. Adding an optional field
// an older build can ignore does not need it.
const FormatVersion = 2

// formatKey holds the version, as an entry of its own. It lives beside
// ingressKey and resolverKey rather than in a wrapper around the names, so
// that a build from before the version existed still reads the file: it sees
// one more entry it has no use for.
const formatKey = "_format"

// ErrNewerFormat reports a registry written by a newer doze than this one.
type ErrNewerFormat struct {
	Path string
	Have int // the version in the file
	Want int // the newest this build understands
}

func (e *ErrNewerFormat) Error() string {
	return fmt.Sprintf("%s is format %d, written by a newer doze than this one (which understands up to %d): "+
		"upgrade this program, or stop every doze program and remove the file", e.Path, e.Have, e.Want)
}

// Entry is one registered name.
type Entry struct {
	IP    string `json:"ip"`
	PID   int    `json:"pid"`
	Owner string `json:"owner"` // "doze" | "doze-aws" | "doze-kafka"
	Tier  Tier   `json:"tier"`
	// Target is where the shared front door proxies this name, "host:port".
	// Empty means the name resolves but is not fronted, which is right for a
	// service that is not HTTP.
	Target string `json:"target,omitempty"`
	// Ports is set where a name's address is translated and not bound (macOS):
	// each public port, and the private port on the gateway it is served on.
	// See Lease.Listen.
	Ports map[string]int `json:"ports,omitempty"`
	// Format is set only on the entry that records the file's format version.
	Format int `json:"format,omitempty"`
}

// Registry is a handle on the shared name file.
type Registry struct {
	path  string
	owner string
	pid   int
}

// Open returns a handle on the registry in the given doze home. It creates
// nothing until something is claimed.
func Open(home, owner string) *Registry {
	return &Registry{path: filepath.Join(home, FileName), owner: owner, pid: os.Getpid()}
}

// Path is the registry file's location.
func (r *Registry) Path() string { return r.path }

// ErrHeld reports that an apex name already belongs to a live process. It is
// not a failure to recover from by retrying: the holder keeps the name until
// it exits, which is the whole point of first-come.
type ErrHeld struct {
	Host  string
	PID   int
	Owner string
}

func (e *ErrHeld) Error() string {
	return fmt.Sprintf("%s is held by pid %d (%s)", e.Host, e.PID, e.Owner)
}

// ErrAddrTaken reports that the address asked for in ClaimAt already belongs to
// another live name.
type ErrAddrTaken struct {
	IP    string
	Host  string // the name that has it
	PID   int
	Owner string
}

func (e *ErrAddrTaken) Error() string {
	return fmt.Sprintf("%s is the address of %s (pid %d, %s)", e.IP, e.Host, e.PID, e.Owner)
}

// Held returns the ErrHeld in err, if any — so a caller can log who holds the
// name and carry on rather than treating it as fatal.
func Held(err error) (*ErrHeld, bool) {
	var h *ErrHeld
	ok := errors.As(err, &h)
	return h, ok
}

// Lease is a claimed name. Release drops it; the serving peer would prune it
// anyway once this process exits, so Release is a courtesy that makes the name
// available again immediately.
type Lease struct {
	Name Name
	IP   net.IP

	reg *Registry
}

// Claim registers a name to this process and returns the address it resolves
// to. An apex name held by another live process returns ErrHeld and no lease.
func (r *Registry) Claim(n Name) (*Lease, error) { return r.claim(n, nil, false) }

// ClaimAt registers a name at an address the caller picked. If the address is
// one of the pool's, it is refused when a different live name already resolves
// there: the pool exists to give each name an address of its own, and two
// names on one would send each other's clients to whichever service bound the
// port first. An address outside the pool — 127.0.0.1, where everything
// listens on a machine with no setup — is shared by design and never refused.
func (r *Registry) ClaimAt(n Name, ip net.IP) (*Lease, error) { return r.claim(n, ip, false) }

// Twin registers a second name at this name's address, for a host that the
// same listeners answer: sync-aws.shop.doze beside aws.shop.doze. It is the
// one way two names share an address from the pool, and it has to be asked
// for: two of a program's services landing on one address by accident is
// still refused.
func (l *Lease) Twin(n Name) (*Lease, error) { return l.reg.claim(n, l.IP, true) }

func (r *Registry) claim(n Name, want net.IP, shared bool) (*Lease, error) {
	var lease *Lease
	err := r.update(func(m map[string]Entry) error {
		if cur, ok := m[n.Host]; ok && cur.PID != r.pid && alive(cur.PID) {
			// Qualified names are per-stack and should not collide; if one
			// does, it is the same conflict and the same answer.
			return &ErrHeld{Host: n.Host, PID: cur.PID, Owner: cur.Owner}
		}
		taken := map[string]bool{}
		for host, e := range m {
			if host != n.Host && e.IP != "" {
				taken[e.IP] = true
			}
		}
		ip := want
		if ip == nil {
			var err error
			if ip, err = addressFor(n, taken); err != nil {
				return err
			}
		} else if inPool(ip) && taken[ip.String()] {
			for host, e := range m {
				if host != n.Host && e.IP == ip.String() && !(shared && e.PID == r.pid) {
					return &ErrAddrTaken{IP: ip.String(), Host: host, PID: e.PID, Owner: e.Owner}
				}
			}
		}
		// Keep any route this process already published, so re-claiming a name
		// (which republishDomains does on every topology change) does not drop
		// it from the front door.
		e := Entry{IP: ip.String(), PID: r.pid, Owner: r.owner, Tier: n.Tier}
		if cur, ok := m[n.Host]; ok && cur.PID == r.pid {
			e.Target = cur.Target
			if cur.IP == e.IP {
				e.Ports = cur.Ports
			}
		}
		m[n.Host] = e
		lease = &Lease{Name: n, IP: ip, reg: r}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lease, nil
}

// Release drops the claim.
func (l *Lease) Release() error {
	if l == nil || l.reg == nil {
		return nil
	}
	return l.reg.update(func(m map[string]Entry) error {
		if e, ok := m[l.Name.Host]; ok && e.PID == l.reg.pid {
			delete(m, l.Name.Host)
		}
		return nil
	})
}

// Snapshot returns the live entries, pruning any whose process has gone.
func (r *Registry) Snapshot() map[string]Entry {
	out := map[string]Entry{}
	_ = r.update(func(m map[string]Entry) error {
		for host, e := range m {
			out[host] = e
		}
		return nil
	})
	return out
}

// Resolve answers a host with its address, or nil if this machine does not
// serve it. This is the function the resolver hands to the DNS server, and it
// answers for EVERY peer's names, not just this process's — which is what
// makes any binary able to serve the whole zone.
func (r *Registry) Resolve(host string) net.IP {
	e, ok := r.lookup(host)
	if !ok {
		return nil
	}
	return net.ParseIP(e.IP).To4()
}

// lookup finds the entry that owns host: the exact match if there is one,
// otherwise the nearest registered ancestor. A registered name owns its whole
// subtree.
//
// That is what lets one process answer for names it never registered and could
// not have registered. doze-aws hands back URLs shaped like AWS's own —
// sqs.ap-south-1.aws.harbour.doze, x70an6eshc.execute-api.ap-south-1.aws.harbour.doze —
// and the API Gateway id in the second is minted at runtime. There is no moment
// at which it could have been claimed in advance, so exact matching cannot serve
// it even in principle.
//
// Two rules keep this from becoming a catch-all, which is the failure this
// change could easily introduce:
//
// The most specific claim wins, because the walk starts at the full name. So an
// apex holder does not swallow the instances beneath it — aws.doze answers for
// sqs.ap-south-1.aws.doze while aws.harbour.doze keeps its own subtree.
//
// The walk stops before the zone itself. Nothing can own ".doze", so a name
// nobody claimed is still NXDOMAIN — "a typo fails as a name that does not
// exist rather than as a connection to the wrong thing", which is the property
// that makes a wrong name debuggable.
func (r *Registry) lookup(host string) (Entry, bool) {
	if !InZone(host) {
		return Entry{}, false
	}
	h := normalize(host)
	m := r.Snapshot()
	for h != Suffix {
		if e, ok := m[h]; ok {
			return e, true
		}
		_, rest, found := strings.Cut(h, ".")
		if !found {
			break
		}
		h = rest
	}
	return Entry{}, false
}

func normalize(host string) string {
	h := host
	for len(h) > 0 && h[len(h)-1] == '.' {
		h = h[:len(h)-1]
	}
	return lower(h)
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// update runs fn against the registry under an exclusive lock, pruning dead
// entries first and writing the result back atomically. Every mutation and
// every read goes through here, so the prune is never skipped.
func (r *Registry) update(fn func(map[string]Entry) error) error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return err
	}
	// The lock is held on a sidecar rather than the registry itself, so the
	// atomic rename below cannot swap the file out from under the lock.
	lock, err := os.OpenFile(r.path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lock.Close()
	unlock, err := lockFile(lock)
	if err != nil {
		return err
	}
	defer unlock()

	m := map[string]Entry{}
	switch raw, err := os.ReadFile(r.path); {
	case err == nil:
		if err := json.Unmarshal(raw, &m); err != nil {
			// A corrupt registry is recoverable: every entry is re-registered
			// by a running process, so starting clean costs at most a restart.
			m = map[string]Entry{}
		}
	case !os.IsNotExist(err):
		return err
	}
	if f, ok := m[formatKey]; ok && f.Format > FormatVersion {
		return &ErrNewerFormat{Path: r.path, Have: f.Format, Want: FormatVersion}
	}
	delete(m, formatKey) // not a name: kept out of every caller's view, stamped back below
	for host, e := range m {
		if !alive(e.PID) {
			delete(m, host)
		}
	}

	if err := fn(m); err != nil {
		return err
	}
	// The stamp carries this process's pid so that a build from before the
	// version existed, which prunes every entry whose process is gone, keeps
	// it for as long as a writer that understands it is running.
	m[formatKey] = Entry{Format: FormatVersion, PID: r.pid, Owner: r.owner}
	defer delete(m, formatKey) // callers that keep m must not see it

	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, append(buf, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// stackPrefix marks the entry that records which project a stack name belongs
// to. Like the other bookkeeping keys it is not an in-zone name.
const stackPrefix = "_stack."

// ErrStackTaken reports that a stack name is in use by another project.
type ErrStackTaken struct {
	Stack string
	Dir   string // the project that has it
	PID   int
}

func (e *ErrStackTaken) Error() string {
	return fmt.Sprintf("stack name %q is already in use by %s (pid %d)", e.Stack, e.Dir, e.PID)
}

// ClaimStack records that the stack called name belongs to the project in dir,
// for as long as this process lives. Every name in a stack is
// <service>.<name>.doze, so two projects with one stack name would answer for
// each other's services; the second is refused and told who has it. The same
// project claiming again — a daemon restarting — takes over its own entry.
//
// It is in the registry, under the registry's lock, for the reason the front
// door's holder is: one file, one lock and one liveness rule, and a crashed
// process frees its name with no cleanup.
func (r *Registry) ClaimStack(name, dir string) (release func(), err error) {
	key := stackPrefix + label(name)
	err = r.update(func(m map[string]Entry) error {
		if cur, ok := m[key]; ok && cur.PID != r.pid && cur.Target != dir {
			return &ErrStackTaken{Stack: name, Dir: cur.Target, PID: cur.PID}
		}
		m[key] = Entry{PID: r.pid, Owner: r.owner, Target: dir}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return func() {
		_ = r.update(func(m map[string]Entry) error {
			if cur, ok := m[key]; ok && cur.PID == r.pid {
				delete(m, key)
			}
			return nil
		})
	}, nil
}

// ReservedStack reports whether a stack may not be called name, because its
// services would collide with a machine-wide name: a stack called "aws" would
// put db.aws.doze under aws.doze, which belongs to whichever local AWS holds
// the apex.
func ReservedStack(name string) bool {
	_, ok := apexOffset[label(name)]
	return ok
}
