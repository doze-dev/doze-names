package names

// The resolver: a small DNS server answering the doze zone from the shared
// registry.
//
// The wire handling here is ported from doze core's internal/daemon/resolver.go
// rather than rewritten — it already handles the awkward parts, in particular
// compressed QNAMEs, which macOS's mDNSResponder produces when it packs the A
// and AAAA questions into one packet with the second name compressed to a
// pointer at the first. Rejecting those silently drops real queries.
//
// What is new here is the take-over loop. In doze core only one daemon ever
// tried, and if it lost the bind it simply never served. With three binaries
// as peers, the process holding the socket may exit while others are still
// running, so every peer keeps trying and the zone survives.

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"
)

// retryInterval is how often a peer that lost the bind tries again. Short
// enough that the zone comes back promptly when the holder exits, long enough
// to be free at idle.
const retryInterval = 2 * time.Second

// Resolve is what the server asks for each in-zone question.
type Resolve func(host string) net.IP

// Server answers the doze zone for as long as it holds the socket. Its methods
// are safe to call whether or not it ever won the bind.
type Server struct {
	cancel context.CancelFunc
	done   chan struct{}
	bound  chan struct{} // closed the first time this process binds
}

// Serve answers the zone from the registry, taking the socket if it is free
// and waiting for it if a peer holds it.
//
// It never fails: not holding the socket is the normal case for every peer but
// one, and it is indistinguishable to callers from holding it — the names
// resolve either way, because whoever does hold it answers from the same
// registry. logf may be nil.
func Serve(ctx context.Context, r *Registry, logf func(string, ...any)) *Server {
	return ServeAt(ctx, r, ResolverAddr(), logf)
}

// ServeResolve is Serve with a caller-supplied resolver, for a host that keeps
// a live view of its own names and wants that consulted before the registry —
// doze core mutates its map as services are added to a running stack, and a
// name should answer the moment it exists rather than after the next write.
func ServeResolve(ctx context.Context, resolve Resolve, logf func(string, ...any)) *Server {
	return serveWith(ctx, resolve, ResolverAddr(), logf, nil)
}

// ServeAt is Serve on a specific address. The zone's address is fixed per
// platform, so this exists for tests — and for anyone routing the zone
// somewhere unusual, where the peer protocol still holds as long as every peer
// on the machine agrees on the address.
func ServeAt(ctx context.Context, r *Registry, addr string, logf func(string, ...any)) *Server {
	return serveWith(ctx, r.Resolve, addr, logf, r)
}

func serveWith(ctx context.Context, resolve Resolve, addr string, logf func(string, ...any), reg *Registry) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{cancel: cancel, done: make(chan struct{}), bound: make(chan struct{})}

	go func() {
		defer close(s.done)
		var announced bool
		for {
			conn, err := listen(addr)
			switch {
			case err == nil:
				select {
				case <-s.bound:
				default:
					close(s.bound)
				}
				logf("names: serving %s on %s", Suffix, addr)
				if reg != nil {
					reg.claimResolver(addr)
				}
				announced = false
				serveConn(ctx, conn, resolve)
				if reg != nil {
					reg.releaseResolver()
				}
				if ctx.Err() != nil {
					return
				}
				// Lost it some other way (socket closed under us): try again.
			case isAddrInUse(err):
				if !announced {
					var h Entry
					var ok bool
					if reg != nil {
						h, ok = reg.ResolverHolder()
					}
					if ok {
						logf("names: %s is serving %s (pid %d); standing by", h.Owner, Suffix, h.PID)
					} else {
						// Not a doze peer. On Linux this is usually
						// systemd-resolved or dnsmasq holding port 53 on the
						// wildcard, which takes every address with it.
						logf("names: something other than doze holds %s, so %s names will not "+
							"resolve through it — apex names still work via the hosts file",
							addr, Suffix)
					}
					announced = true
				}
			default:
				if !announced {
					logf("names: cannot serve %s (%v); names will not resolve", Suffix, err)
					announced = true
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryInterval):
			}
		}
	}()
	return s
}

// Bound blocks until this process holds the socket, or ctx ends. Mostly for
// tests — production callers do not care which peer is serving.
func (s *Server) Bound(ctx context.Context) bool {
	select {
	case <-s.bound:
		return true
	case <-ctx.Done():
		return false
	}
}

// Close stops serving and releases the socket, letting a peer take over.
func (s *Server) Close() {
	s.cancel()
	<-s.done
}

func listen(addr string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", ua)
}

func serveConn(ctx context.Context, conn *net.UDPConn, resolve Resolve) {
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if resp := answer(buf[:n], resolve); resp != nil {
			_, _ = conn.WriteToUDP(resp, addr)
		}
	}
}

const (
	typeA    = 1
	typeAAAA = 28
)

// answer builds the response to one query: an A record for an in-zone name
// this machine serves, an empty NOERROR for in-zone non-A questions (so the
// client falls back to the A answer rather than retrying), and NXDOMAIN for
// anything else. Nil for input that cannot be parsed.
func answer(q []byte, resolve Resolve) []byte {
	if len(q) < 12 {
		return nil
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil // one question per query, like every real client sends
	}
	name, qtype, qend, ok := parseQuestion(q, 12)
	if !ok {
		return nil
	}

	var ip net.IP
	inZone := InZone(name)
	if inZone && resolve != nil {
		if r := resolve(name); r != nil {
			ip = r.To4()
		}
	}

	resp := make([]byte, 0, qend+16)
	resp = append(resp, q[0], q[1])
	flags := uint16(0x8080) | (binary.BigEndian.Uint16(q[2:4]) & 0x0100) // QR|RA, echo RD
	var rcode, answers uint16
	switch {
	case !inZone || ip == nil:
		rcode = 3 // NXDOMAIN — not a name this machine serves
	case qtype == typeA:
		answers = 1
	}

	resp = binary.BigEndian.AppendUint16(resp, flags|rcode)
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint16(resp, answers)
	resp = binary.BigEndian.AppendUint16(resp, 0)
	resp = binary.BigEndian.AppendUint16(resp, 0)
	resp = append(resp, q[12:qend]...) // the question, verbatim

	if answers == 1 {
		resp = append(resp, 0xC0, 0x0C) // name: pointer to the question
		resp = binary.BigEndian.AppendUint16(resp, typeA)
		resp = binary.BigEndian.AppendUint16(resp, 1) // IN
		// Short TTL: services come and go, and a stale cached answer is a
		// connection to nothing.
		resp = binary.BigEndian.AppendUint32(resp, 10)
		resp = binary.BigEndian.AppendUint16(resp, 4)
		resp = append(resp, ip[0], ip[1], ip[2], ip[3])
	}
	return resp
}

// parseQuestion reads one question, returning the lowercase dotted name and
// the offset just past it.
func parseQuestion(q []byte, off int) (name string, qtype uint16, end int, ok bool) {
	name, end, ok = parseName(q, off)
	if !ok || end+4 > len(q) {
		return "", 0, 0, false
	}
	return name, binary.BigEndian.Uint16(q[end : end+2]), end + 4, true
}

// parseName decodes a possibly-compressed name at off, returning the offset
// just past its encoding at the ORIGINAL position — following a pointer must
// not advance the caller past the pointer itself.
func parseName(q []byte, off int) (name string, end int, ok bool) {
	var labels []string
	pos, jumps := off, 0
	for {
		if pos >= len(q) {
			return "", 0, false
		}
		l := int(q[pos])
		switch {
		case l == 0:
			if end == 0 {
				end = pos + 1
			}
			return strings.Join(labels, "."), end, true
		case l&0xC0 == 0xC0: // compression pointer
			if pos+1 >= len(q) {
				return "", 0, false
			}
			if end == 0 {
				end = pos + 2
			}
			if jumps++; jumps > 8 {
				return "", 0, false // pointer loop
			}
			pos = int(binary.BigEndian.Uint16(q[pos:pos+2]) & 0x3FFF)
		default:
			if pos+1+l > len(q) {
				return "", 0, false
			}
			labels = append(labels, strings.ToLower(string(q[pos+1:pos+1+l])))
			pos += 1 + l
		}
	}
}

func isAddrInUse(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) {
		return errors.Is(op.Err, syscall.EADDRINUSE)
	}
	return errors.Is(err, syscall.EADDRINUSE)
}
