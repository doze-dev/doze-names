package names

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// slowChecksum is the internet checksum written the obvious way.
func slowChecksum(b []byte, sum uint32) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

func TestChecksumMatchesTheObviousOne(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 600; n++ {
		b := make([]byte, n)
		rng.Read(b)
		seed := rng.Uint32() >> 12
		if got, want := checksum(b, seed), slowChecksum(b, seed); got != want {
			t.Fatalf("checksum of %d bytes = %#04x, want %#04x", n, got, want)
		}
	}
	ff := make([]byte, 4096)
	for i := range ff {
		ff[i] = 0xff
	}
	if got, want := checksum(ff, 0xffff), slowChecksum(ff, 0xffff); got != want {
		t.Fatalf("checksum of all ones = %#04x, want %#04x", got, want)
	}
}

var (
	gw  = [4]byte{198, 19, 0, 1}
	dbV = [4]byte{198, 19, 3, 7}
)

// one address, with 5432 served on private port 51000.
func dbTable() *portTable {
	return &portTable{
		toPrivate: map[[4]byte]map[uint16]uint16{dbV: {5432: 51000}},
		toPublic:  map[[4]byte]map[uint16]uint16{dbV: {51000: 5432}},
	}
}

// tcp builds a TCP packet with a correct checksum.
func tcp(src, dst [4]byte, sport, dport uint16, flags byte, seq, ack uint32, payload string) []byte {
	p := make([]byte, 40+len(payload))
	p[0], p[8], p[9] = 0x45, 64, protoTCP
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	t := p[20:]
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], ack)
	t[12], t[13] = 5<<4, flags
	binary.BigEndian.PutUint16(t[14:], 65535)
	copy(t[20:], payload)
	setAddrs(p, 20, src, dst)
	tcpChecksum(p, 20, len(p))
	return p
}

type seen struct {
	src, dst     [4]byte
	sport, dport uint16
	flags        byte
	seq, ack     uint32
	payload      string
}

// read takes a packet apart, failing if either checksum is wrong.
func read(t *testing.T, p []byte) seen {
	t.Helper()
	total := packetLen(p)
	if slowChecksum(p[:20], 0) != 0 {
		t.Fatal("the IP header checksum is wrong")
	}
	seg := p[20:total]
	pseudo := uint32(binary.BigEndian.Uint16(p[12:])) + uint32(binary.BigEndian.Uint16(p[14:])) +
		uint32(binary.BigEndian.Uint16(p[16:])) + uint32(binary.BigEndian.Uint16(p[18:])) + protoTCP + uint32(len(seg))
	if slowChecksum(seg, pseudo) != 0 {
		t.Fatal("the TCP checksum is wrong")
	}
	var s seen
	copy(s.src[:], p[12:16])
	copy(s.dst[:], p[16:20])
	s.sport, s.dport = binary.BigEndian.Uint16(seg[0:]), binary.BigEndian.Uint16(seg[2:])
	s.seq, s.ack = binary.BigEndian.Uint32(seg[4:]), binary.BigEndian.Uint32(seg[8:])
	s.flags, s.payload = seg[13], string(seg[int(seg[12]>>4)*4:])
	return s
}

// A client's packet to the service's address becomes one from that address to
// the service's private port, and the answer is turned round to match.
func TestAConnectionIsTranslatedBothWays(t *testing.T) {
	out := tcp(gw, dbV, 49200, 5432, tcpACK, 100, 200, "select 1")
	if !translate(out, gw, dbTable()) {
		t.Fatal("the client's packet was dropped")
	}
	if got, want := read(t, out), (seen{dbV, gw, 49200, 51000, tcpACK, 100, 200, "select 1"}); got != want {
		t.Fatalf("to the service:\n got %+v\nwant %+v", got, want)
	}

	back := tcp(gw, dbV, 51000, 49200, tcpACK, 200, 108, "1 row")
	if !translate(back, gw, dbTable()) {
		t.Fatal("the service's answer was dropped")
	}
	if got, want := read(t, back), (seen{dbV, gw, 5432, 49200, tcpACK, 200, 108, "1 row"}); got != want {
		t.Fatalf("to the client:\n got %+v\nwant %+v", got, want)
	}
}

// Nothing registered the port: the client is refused at once, as it would be
// by a closed port, instead of waiting for a timeout.
func TestAnUnregisteredPortIsRefused(t *testing.T) {
	syn := tcp(gw, dbV, 49200, 6379, tcpSYN, 1000, 0, "")
	if !translate(syn, gw, dbTable()) {
		t.Fatal("the connection attempt was dropped, which a client sees as a hang")
	}
	if got, want := read(t, syn), (seen{dbV, gw, 6379, 49200, tcpRST | tcpACK, 0, 1001, ""}); got != want {
		t.Fatalf("the refusal:\n got %+v\nwant %+v", got, want)
	}

	// Mid-connection, to a service that has gone: reset from where it left off.
	data := tcp(gw, dbV, 49200, 6379, tcpACK, 1001, 777, "ping")
	if !translate(data, gw, dbTable()) {
		t.Fatal("data to a port that has gone was dropped")
	}
	if got, want := read(t, data), (seen{dbV, gw, 6379, 49200, tcpRST, 777, 0, ""}); got != want {
		t.Fatalf("the reset:\n got %+v\nwant %+v", got, want)
	}

	// A reset is never answered with a reset.
	if translate(tcp(gw, dbV, 49200, 6379, tcpRST, 1, 0, ""), gw, dbTable()) {
		t.Fatal("a reset was answered")
	}
}

func TestPingIsAnswered(t *testing.T) {
	p := make([]byte, 20+8+5)
	p[0], p[8], p[9] = 0x45, 64, protoICMP
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	icmp := p[20:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:], 7) // id
	copy(icmp[8:], "hello")
	binary.BigEndian.PutUint16(icmp[2:], slowChecksum(icmp, 0))
	setAddrs(p, 20, gw, dbV)

	if !translate(p, gw, dbTable()) {
		t.Fatal("the ping was dropped")
	}
	if p[20] != 0 || slowChecksum(p[20:], 0) != 0 || string(p[28:]) != "hello" {
		t.Fatalf("not an echo reply with the same payload: % x", p[20:])
	}
	if [4]byte(p[12:16]) != dbV || [4]byte(p[16:20]) != gw {
		t.Fatalf("the reply goes from % d to % d", p[12:16], p[16:20])
	}
}

// What is not this machine talking to the block is left alone.
func TestOtherPacketsAreDropped(t *testing.T) {
	stranger := [4]byte{10, 0, 0, 9}
	for name, p := range map[string][]byte{
		"from another source":   tcp(stranger, dbV, 49200, 5432, tcpSYN, 1, 0, ""),
		"to the gateway itself": tcp(gw, gw, 49200, 5432, tcpSYN, 1, 0, ""),
		"too short":             tcp(gw, dbV, 49200, 5432, tcpSYN, 1, 0, "")[:30],
		"not IPv4":              append([]byte{0x60}, make([]byte, 60)...),
	} {
		if translate(p, gw, dbTable()) {
			t.Errorf("%s: translated, want dropped", name)
		}
	}
	frag := tcp(gw, dbV, 49200, 5432, tcpACK, 1, 1, "x")
	binary.BigEndian.PutUint16(frag[6:], 0x2000)
	if translate(frag, gw, dbTable()) {
		t.Error("a fragment was translated")
	}
}
