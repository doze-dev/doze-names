package names

// How a service listens on its name.
//
// On Linux a name's address is local and the service binds it. On macOS it is
// not (see pool.go): the service listens on a private port and registers which
// public port that stands for, and the daemon translates. Listen hides the
// difference, and is the one call doze, doze-aws and doze-kafka all make, so a
// service is reached at <name>:<port> on either system without any of them
// knowing which it is on.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
)

// Listen opens a TCP listener for one of this name's ports: clients reach it
// at the name's address on that port. The listener's Addr is that public
// address, whatever it is really bound to.
func (l *Lease) Listen(port int) (net.Listener, error) {
	if !l.translated() {
		return net.Listen("tcp", net.JoinHostPort(l.IP.String(), strconv.Itoa(port)))
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(zone.gateway().String(), "0"))
	if err != nil {
		return nil, fmt.Errorf("%s: the doze network is not running (run setup): %w", l.Name.Host, err)
	}
	if err := l.Forward(port, ln.Addr().(*net.TCPAddr).Port); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &listener{Listener: ln, lease: l, port: port}, nil
}

// BindAddr is the address a process should listen on to serve one of this
// name's ports, for a server this program starts but does not run in-process:
// pick a free port on BindAddr, have the server listen there, and Forward the
// public port to it. On Linux it is the name's own address and Forward does
// nothing, so the server can simply take the public port.
func (l *Lease) BindAddr() net.IP {
	if l.translated() {
		return zone.gateway()
	}
	return l.IP
}

// Forward registers that this name's public port is served on a private port
// of BindAddr. It replaces whatever the port was forwarded to. Where the
// address is bound directly there is nothing to register.
func (l *Lease) Forward(public, private int) error {
	if !l.translated() {
		return nil
	}
	return l.setPort(public, private)
}

// Unforward drops a port registered with Forward.
func (l *Lease) Unforward(public int) error {
	if !l.translated() {
		return nil
	}
	return l.setPort(public, 0)
}

// translated reports whether this name's address is one the daemon translates
// and not one that can be bound.
func (l *Lease) translated() bool {
	if !zone.virtual {
		return false
	}
	_, ok := zone.offset(l.IP)
	return ok
}

func (l *Lease) setPort(public, private int) error {
	if public <= 0 || public > 65535 {
		return fmt.Errorf("%s: port %d is not a port", l.Name.Host, public)
	}
	return l.reg.update(func(m map[string]Entry) error {
		e, ok := m[l.Name.Host]
		if !ok || e.PID != l.reg.pid {
			return fmt.Errorf("%s is not held by this process", l.Name.Host)
		}
		ports := map[string]int{}
		for k, v := range e.Ports {
			ports[k] = v
		}
		if private == 0 {
			delete(ports, strconv.Itoa(public))
		} else {
			ports[strconv.Itoa(public)] = private
		}
		e.Ports = ports
		if len(ports) == 0 {
			e.Ports = nil
		}
		m[l.Name.Host] = e
		return nil
	})
}

// listener is a translated port's listener. It answers for the public address
// and takes the registration with it when it closes.
type listener struct {
	net.Listener
	lease *Lease
	port  int
}

func (ln *listener) Addr() net.Addr {
	return &net.TCPAddr{IP: ln.lease.IP, Port: ln.port}
}

func (ln *listener) Close() error {
	_ = ln.lease.Unforward(ln.port)
	return ln.Listener.Close()
}

// portTable is every live name's registered ports, by address: what the daemon
// translates from. It is built from the registry file as it stands, without the
// lock and without rewriting it — the file is replaced atomically, so a read
// is always of one whole version.
type portTable struct {
	toPrivate map[[4]byte]map[uint16]uint16
	toPublic  map[[4]byte]map[uint16]uint16
}

func (t *portTable) private(v [4]byte, public uint16) (uint16, bool) {
	p, ok := t.toPrivate[v][public]
	return p, ok
}

func (t *portTable) public(v [4]byte, private uint16) (uint16, bool) {
	p, ok := t.toPublic[v][private]
	return p, ok
}

// frontDoorPort is the port every routed name is served on by the shared front
// door, which listens on the wildcard and so on the gateway too.
const frontDoorPort = 80

// readPortTable builds the table from the registry at path. A name whose
// process is gone is left out: its private port may already belong to
// something else.
func readPortTable(path string, n network) *portTable {
	t := &portTable{toPrivate: map[[4]byte]map[uint16]uint16{}, toPublic: map[[4]byte]map[uint16]uint16{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		return t
	}
	m := map[string]Entry{}
	if json.Unmarshal(raw, &m) != nil {
		return t
	}
	frontDoor := m[ingressKey]
	for host, e := range m {
		if !InZone(host) || !alive(e.PID) {
			continue
		}
		ip := net.ParseIP(e.IP)
		if _, ok := n.offset(ip); !ok {
			continue
		}
		var v [4]byte
		copy(v[:], ip.To4())
		add := func(public, private uint16) {
			if t.toPrivate[v] == nil {
				t.toPrivate[v], t.toPublic[v] = map[uint16]uint16{}, map[uint16]uint16{}
			}
			t.toPrivate[v][public], t.toPublic[v][private] = private, public
		}
		for k, private := range e.Ports {
			if public, err := strconv.Atoi(k); err == nil && public > 0 && public < 65536 && private > 0 && private < 65536 {
				add(uint16(public), uint16(private))
			}
		}
		// A routed name is answered by the front door unless the service took
		// port 80 for itself.
		if _, own := e.Ports[strconv.Itoa(frontDoorPort)]; !own && e.Target != "" && alive(frontDoor.PID) {
			if frontDoor.Target == ingressBind {
				add(frontDoorPort, frontDoorPort)
			}
		}
	}
	return t
}

// Listen opens a TCP listener on addr, "ip:port", for whichever of this
// process's names has that address: Lease.Listen for a caller that carries
// addresses about and not leases. An address that is no name's — 127.0.0.1 on
// a machine with no setup — is simply listened on.
func (r *Registry) Listen(addr string) (net.Listener, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if _, ok := zone.offset(ip); !zone.virtual || !ok {
		return net.Listen("tcp", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %q is not a port", addr, portStr)
	}
	for name, e := range r.Snapshot() {
		if e.PID == r.pid && e.IP == ip.String() && InZone(name) {
			l := &Lease{Name: Name{Host: name, Tier: e.Tier}, IP: ip.To4(), reg: r}
			return l.Listen(port)
		}
	}
	return nil, fmt.Errorf("listen %s: no name of this program has that address", addr)
}
