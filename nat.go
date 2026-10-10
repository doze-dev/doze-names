package names

// The translation the macOS daemon does to every packet (see netd_darwin.go).
//
// A client connects to a service's address V on its public port: db.shop.doze
// is 198.19.3.7, port 5432. V is routed to the daemon's interface, so the
// kernel hands the daemon the packet, from the interface's own address G:
//
//	G:sport → V:5432
//
// The service is really listening on G, on a private port it registered. The
// daemon rewrites the packet as though V had sent it to that port, and writes
// it back, which delivers it:
//
//	V:sport → G:private
//
// The service answers V, which again comes to the daemon, and is turned round
// the same way:
//
//	G:private → V:sport    becomes    V:5432 → G:sport
//
// So the client talks to V:5432 and the service to a peer called V, and both
// ends are the kernel's own TCP. Nothing here keeps a connection: a packet is
// translated from the registered ports alone, so there is no table to fill, no
// idle connection to forget, and a daemon that restarts picks up where it was.

import "encoding/binary"

// forwards is the registered ports of every address.
type forwards interface {
	// private returns the port address v's public port is listened on.
	private(v [4]byte, public uint16) (uint16, bool)
	// public returns the public port that one of v's private ports stands for.
	public(v [4]byte, private uint16) (uint16, bool)
}

const (
	protoICMP = 1
	protoTCP  = 6

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// translate rewrites one IPv4 packet read from the interface, in place, and
// reports whether it should be written back. gw is the interface's address.
func translate(p []byte, gw [4]byte, f forwards) bool {
	if len(p) < 20 || p[0]>>4 != 4 {
		return false
	}
	ihl := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:]))
	if ihl < 20 || total < ihl || total > len(p) {
		return false
	}
	if binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
		return false // a fragment: nothing local sends one over this interface
	}
	var src, dst [4]byte
	copy(src[:], p[12:16])
	copy(dst[:], p[16:20])
	if src != gw || dst == gw {
		return false
	}
	body := p[ihl:total]

	switch p[9] {
	case protoICMP:
		if len(body) < 8 || body[0] != 8 { // echo request only
			return false
		}
		body[0] = 0
		body[2], body[3] = 0, 0
		binary.BigEndian.PutUint16(body[2:], checksum(body, 0))
		setAddrs(p, ihl, dst, src)
		return true

	case protoTCP:
		if len(body) < 20 {
			return false
		}
		sport := binary.BigEndian.Uint16(body[0:])
		dport := binary.BigEndian.Uint16(body[2:])
		// The service's answer is looked for first. Its source port is one the
		// service is listening on at this address, which the kernel never
		// gives a client as its own, so the two cannot be confused.
		if pub, ok := f.public(dst, sport); ok {
			binary.BigEndian.PutUint16(body[0:], pub)
		} else if priv, ok := f.private(dst, dport); ok {
			binary.BigEndian.PutUint16(body[2:], priv)
		} else {
			return refuse(p, ihl, total)
		}
		setAddrs(p, ihl, dst, src)
		tcpChecksum(p, ihl, total)
		return true
	}
	return false
}

// refuse turns a TCP packet for a port nothing registered into the reset that
// answers it, so a client is refused at once instead of waiting out a timeout
// — the same answer a closed port gives anywhere else.
func refuse(p []byte, ihl, total int) bool {
	body := p[ihl:total]
	flags := body[13]
	if flags&tcpRST != 0 {
		return false
	}
	var src, dst [4]byte
	copy(src[:], p[12:16])
	copy(dst[:], p[16:20])
	sport := binary.BigEndian.Uint16(body[0:])
	dport := binary.BigEndian.Uint16(body[2:])
	seq := binary.BigEndian.Uint32(body[4:])
	ack := binary.BigEndian.Uint32(body[8:])
	seglen := uint32(len(body) - int(body[12]>>4)*4)
	if flags&tcpSYN != 0 {
		seglen++
	}
	if flags&tcpFIN != 0 {
		seglen++
	}

	// The reset is a bare 20-byte header on a 20-byte IP header.
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], 40)
	binary.BigEndian.PutUint16(p[6:], 0)
	p[8] = 64
	t := p[20:40]
	binary.BigEndian.PutUint16(t[0:], dport)
	binary.BigEndian.PutUint16(t[2:], sport)
	if flags&tcpACK != 0 {
		binary.BigEndian.PutUint32(t[4:], ack)
		binary.BigEndian.PutUint32(t[8:], 0)
		t[13] = tcpRST
	} else {
		binary.BigEndian.PutUint32(t[4:], 0)
		binary.BigEndian.PutUint32(t[8:], seq+seglen)
		t[13] = tcpRST | tcpACK
	}
	t[12] = 5 << 4
	t[14], t[15] = 0, 0 // window
	t[18], t[19] = 0, 0 // urgent
	setAddrs(p, 20, dst, src)
	tcpChecksum(p, 20, 40)
	return true
}

// packetLen is the length of the packet translate left in p.
func packetLen(p []byte) int { return int(binary.BigEndian.Uint16(p[2:])) }

// setAddrs writes the packet's addresses and its header checksum.
func setAddrs(p []byte, ihl int, src, dst [4]byte) {
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:], checksum(p[:ihl], 0))
}

// tcpChecksum writes the TCP checksum, over the segment and the addresses.
// It is worked out whole and not adjusted: a packet from this machine's own
// stack can arrive with the checksum left for hardware to fill in.
func tcpChecksum(p []byte, ihl, total int) {
	seg := p[ihl:total]
	seg[16], seg[17] = 0, 0
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(p[12:])) + uint32(binary.BigEndian.Uint16(p[14:]))
	sum += uint32(binary.BigEndian.Uint16(p[16:])) + uint32(binary.BigEndian.Uint16(p[18:]))
	sum += protoTCP + uint32(len(seg))
	binary.BigEndian.PutUint16(seg[16:], checksum(seg, sum))
}

// checksum is the internet checksum of b, continued from sum.
func checksum(b []byte, sum uint32) uint16 {
	n := len(b)
	i := 0
	for ; i+8 <= n; i += 8 {
		v := binary.BigEndian.Uint64(b[i:])
		sum64 := uint64(sum) + (v >> 32) + (v & 0xffffffff)
		sum = uint32(sum64>>32) + uint32(sum64)
		if sum < uint32(sum64) {
			sum++
		}
	}
	// What is in sum now is a sum of 32-bit words; fold the rest in as 16-bit.
	s := uint64(sum>>16) + uint64(sum&0xffff)
	for ; i+2 <= n; i += 2 {
		s += uint64(binary.BigEndian.Uint16(b[i:]))
	}
	if i < n {
		s += uint64(b[i]) << 8
	}
	for s>>16 != 0 {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}
