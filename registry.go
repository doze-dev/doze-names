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
	"syscall"
)

// FileName is the registry's name inside the doze home.
const FileName = "names.json"

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
func (r *Registry) Claim(n Name) (*Lease, error) { return r.claim(n, nil) }

// ClaimAt registers a name at an address the caller picked, for a host that
// runs its own allocator — doze core assigns per-(stack, service) addresses and
// persists them, so its names must keep the addresses it already handed out
// rather than be rehashed here.
func (r *Registry) ClaimAt(n Name, ip net.IP) (*Lease, error) { return r.claim(n, ip) }

func (r *Registry) claim(n Name, want net.IP) (*Lease, error) {
	var lease *Lease
	err := r.update(func(m map[string]Entry) error {
		if cur, ok := m[n.Host]; ok && cur.PID != r.pid && alive(cur.PID) {
			// Qualified names are per-stack and should not collide; if one
			// does, it is the same conflict and the same answer.
			return &ErrHeld{Host: n.Host, PID: cur.PID, Owner: cur.Owner}
		}
		taken := map[string]bool{}
		for host, e := range m {
			if host != n.Host {
				taken[e.IP] = true
			}
		}
		ip := want
		if ip == nil {
			var err error
			if ip, err = addressFor(n, taken); err != nil {
				return err
			}
		}
		// Keep any route this process already published, so re-claiming a name
		// (which republishDomains does on every topology change) does not drop
		// it from the front door.
		e := Entry{IP: ip.String(), PID: r.pid, Owner: r.owner, Tier: n.Tier}
		if cur, ok := m[n.Host]; ok && cur.PID == r.pid {
			e.Target = cur.Target
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
	if !InZone(host) {
		return nil
	}
	e, ok := r.Snapshot()[normalize(host)]
	if !ok {
		return nil
	}
	return net.ParseIP(e.IP).To4()
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
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

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
	for host, e := range m {
		if !alive(e.PID) {
			delete(m, host)
		}
	}

	if err := fn(m); err != nil {
		return err
	}

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

// alive reports whether a process exists. Signal 0 checks for existence
// without delivering anything; EPERM means it exists and belongs to someone
// else, which still counts as alive.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
