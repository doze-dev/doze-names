package names

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// query builds a minimal DNS A query for host.
func query(host string, qtype uint16) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(q[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(q[4:6], 1)      // QDCOUNT
	for _, l := range splitLabels(host) {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1) // IN
	return q
}

func splitLabels(host string) []string {
	var out []string
	cur := ""
	for _, c := range host {
		if c == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func rcodeOf(resp []byte) uint16   { return binary.BigEndian.Uint16(resp[2:4]) & 0x000F }
func ancountOf(resp []byte) uint16 { return binary.BigEndian.Uint16(resp[6:8]) }

func staticResolve(m map[string]string) Resolve {
	return func(host string) net.IP {
		if ip, ok := m[host]; ok {
			return net.ParseIP(ip)
		}
		return nil
	}
}

func TestAnswer(t *testing.T) {
	resolve := staticResolve(map[string]string{"aws.doze": "127.0.0.2"})

	t.Run("A record for a name we serve", func(t *testing.T) {
		resp := answer(query("aws.doze", typeA), resolve)
		if resp == nil {
			t.Fatal("no response")
		}
		if rcodeOf(resp) != 0 || ancountOf(resp) != 1 {
			t.Fatalf("rcode=%d ancount=%d, want 0/1", rcodeOf(resp), ancountOf(resp))
		}
		ip := net.IP(resp[len(resp)-4:])
		if ip.String() != "127.0.0.2" {
			t.Errorf("answered %v, want 127.0.0.2", ip)
		}
		if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
			t.Error("response did not echo the query ID")
		}
	})

	t.Run("AAAA is an empty NOERROR, not NXDOMAIN", func(t *testing.T) {
		// A client that gets NXDOMAIN for AAAA may not fall back to the A
		// record; an empty NOERROR tells it the name exists with no v6 address.
		resp := answer(query("aws.doze", typeAAAA), resolve)
		if rcodeOf(resp) != 0 || ancountOf(resp) != 0 {
			t.Fatalf("rcode=%d ancount=%d, want 0/0", rcodeOf(resp), ancountOf(resp))
		}
	})

	t.Run("in-zone but unregistered is NXDOMAIN", func(t *testing.T) {
		if got := rcodeOf(answer(query("nope.doze", typeA), resolve)); got != 3 {
			t.Errorf("rcode = %d, want 3", got)
		}
	})

	t.Run("out of zone is NXDOMAIN", func(t *testing.T) {
		if got := rcodeOf(answer(query("example.com", typeA), resolve)); got != 3 {
			t.Errorf("rcode = %d, want 3", got)
		}
	})

	t.Run("truncated input is dropped, not answered", func(t *testing.T) {
		if resp := answer([]byte{1, 2, 3}, resolve); resp != nil {
			t.Error("answered a malformed query")
		}
	})

	t.Run("compressed QNAME", func(t *testing.T) {
		// macOS's mDNSResponder packs A and AAAA into one packet with the
		// second name compressed to a pointer at the first. A parser that
		// rejects pointers silently drops real queries.
		base := query("aws.doze", typeA)
		const nameStart = 12
		// The question's QNAME is a two-byte pointer, and the name it points at
		// is parked after the question — at nameStart + 2 (pointer) + 4
		// (qtype/qclass), which is where the append below lands it.
		const target = nameStart + 2 + 4
		compressed := append([]byte{}, base[:nameStart]...)
		compressed = append(compressed, 0xC0, byte(target))
		compressed = binary.BigEndian.AppendUint16(compressed, typeA)
		compressed = binary.BigEndian.AppendUint16(compressed, 1)
		if len(compressed) != target {
			t.Fatalf("name parked at %d, pointer says %d", len(compressed), target)
		}
		compressed = append(compressed, base[nameStart:]...)
		if resp := answer(compressed, resolve); resp == nil || ancountOf(resp) != 1 {
			t.Fatal("a compressed QNAME was not answered")
		}
	})
}

// freeUDPAddr returns a loopback address with a port nothing is using, so the
// peer tests never collide with a real doze daemon on this machine.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}

func ask(t *testing.T, addr, host string) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(query(host, typeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer for %s: %v", host, err)
	}
	return buf[:n]
}

func TestOnePeerServesEveryPeersNames(t *testing.T) {
	// The requirement: whichever binary you installed powers the zone for all
	// of them. doze-kafka holds the socket; doze-aws never binds; aws.doze
	// still resolves.
	home, addr := t.TempDir(), freeUDPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kafka := Open(home, "doze-kafka")
	if _, err := kafka.Claim(Apex("kafka")); err != nil {
		t.Fatal(err)
	}
	holder := ServeAt(ctx, kafka, addr, nil)
	defer holder.Close()
	if !holder.Bound(waitCtx(t)) {
		t.Fatal("first peer never bound")
	}

	// doze-aws starts later. It gets the registry but not the socket.
	aws := Open(home, "doze-aws")
	if _, err := aws.Claim(Apex("aws")); err != nil {
		t.Fatal(err)
	}
	standby := ServeAt(ctx, aws, addr, nil)
	defer standby.Close()

	// Exactly one peer serves: the second must defer rather than fight for the
	// socket. Without this the test would pass even if both had bound.
	brief, cancelBrief := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelBrief()
	if standby.Bound(brief) {
		t.Error("second peer took the socket while a peer already held it")
	}

	for host, want := range map[string]string{"kafka.doze": "127.0.0.3", "aws.doze": "127.0.0.2"} {
		resp := ask(t, addr, host)
		if ancountOf(resp) != 1 {
			t.Fatalf("%s: ancount=%d, want 1", host, ancountOf(resp))
		}
		if got := net.IP(resp[len(resp)-4:]).String(); got != want {
			t.Errorf("%s = %s, want %s", host, got, want)
		}
	}
}

func TestPeerTakesOverWhenTheHolderExits(t *testing.T) {
	home, addr := t.TempDir(), freeUDPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kafka := Open(home, "doze-kafka")
	if _, err := kafka.Claim(Apex("kafka")); err != nil {
		t.Fatal(err)
	}
	holder := ServeAt(ctx, kafka, addr, nil)
	if !holder.Bound(waitCtx(t)) {
		t.Fatal("first peer never bound")
	}

	aws := Open(home, "doze-aws")
	if _, err := aws.Claim(Apex("aws")); err != nil {
		t.Fatal(err)
	}
	standby := ServeAt(ctx, aws, addr, nil)
	defer standby.Close()

	// The holder goes away. Without the retry loop the zone would stay dark
	// for as long as the remaining peers keep running.
	holder.Close()
	if !standby.Bound(waitCtx(t)) {
		t.Fatal("standby never took the socket over")
	}
	if ancountOf(ask(t, addr, "aws.doze")) != 1 {
		t.Error("zone did not answer after take-over")
	}
}

func waitCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*retryInterval)
	t.Cleanup(cancel)
	return ctx
}
