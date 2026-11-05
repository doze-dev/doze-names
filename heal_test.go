package names

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

// A program built before Entry.Ports rewrites the shared file without them;
// the process that set them puts them back, so the network daemon keeps
// answering for the name.
func TestAForwardLostToAnOlderWriterIsPutBack(t *testing.T) {
	machine(t, translatedLoopback, all)
	home := t.TempDir()
	r := Open(home, "doze")
	lease, err := r.Claim(Qualified("db", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := lease.Listen(5432)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	want := r.Snapshot()["db.shop.doze"].Ports["5432"]
	if want == 0 {
		t.Fatal("no forward registered")
	}

	// The older writer: read every entry into a type with no ports, write
	// them back.
	type oldEntry struct {
		IP     string `json:"ip,omitempty"`
		PID    int    `json:"pid"`
		Owner  string `json:"owner,omitempty"`
		Tier   string `json:"tier,omitempty"`
		Target string `json:"target,omitempty"`
	}
	raw, err := os.ReadFile(r.Path())
	if err != nil {
		t.Fatal(err)
	}
	old := map[string]oldEntry{}
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	stripped, _ := json.Marshal(old)
	time.Sleep(10 * time.Millisecond) // a stamp the healer has not seen
	if err := os.WriteFile(r.Path(), stripped, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := r.Snapshot()["db.shop.doze"].Ports; len(got) != 0 {
		t.Fatalf("the older writer did not strip the ports: %v", got)
	}
	// The network daemon does not wait for the heal: the ports file still
	// has the mapping, and the table reads both.
	ip := r.Snapshot()["db.shop.doze"].IP
	var v [4]byte
	copy(v[:], net.ParseIP(ip).To4())
	if got := readPortTable(r.Path(), translatedLoopback).toPrivate[v][5432]; int(got) != want {
		t.Fatalf("the table sends 5432 to %d with the registry stripped, want %d", got, want)
	}

	deadline := time.Now().Add(3 * healEvery)
	for time.Now().Before(deadline) {
		if got := r.Snapshot()["db.shop.doze"].Ports["5432"]; got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the forward 5432 → %s was not put back: %v", strconv.Itoa(want), r.Snapshot()["db.shop.doze"].Ports)
}

// Releasing a name takes its ports out of the ports file too, so nothing
// that reads it later translates for an address no one holds.
func TestReleaseDropsKeptPorts(t *testing.T) {
	machine(t, translatedLoopback, all)
	home := t.TempDir()
	r := Open(home, "doze")
	lease, err := r.Claim(Qualified("db", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := lease.Listen(5432)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := readPorts(r.Path())["db.shop.doze"]; !ok {
		t.Fatal("ports file has no entry after Listen")
	}
	_ = ln.Close()
	_ = lease.Release()
	if e, ok := readPorts(r.Path())["db.shop.doze"]; ok {
		t.Fatalf("ports file still has %v after Release", e)
	}
	r.fwdMu.Lock()
	n := len(r.forwards)
	r.fwdMu.Unlock()
	if n != 0 {
		t.Fatalf("healer still keeps %d names after Release", n)
	}
}

// Ports kept for one address are not used for the name at another.
func TestKeptPortsFollowTheAddress(t *testing.T) {
	machine(t, translatedLoopback, all)
	home := t.TempDir()
	r := Open(home, "doze")
	lease, err := r.Claim(Qualified("db", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := lease.Listen(5432)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	side := readPorts(r.Path())
	e := side["db.shop.doze"]
	if e.IP != lease.IP.String() {
		t.Fatalf("ports file IP = %q, want %q", e.IP, lease.IP)
	}
	e.IP = "198.19.9.9"
	side["db.shop.doze"] = e
	b, _ := json.Marshal(side)
	if err := os.WriteFile(portsPath(r.Path()), b, 0o644); err != nil {
		t.Fatal(err)
	}
	// Strip the registry's own copy, so only the side file could supply it,
	// with the healer stopped so it does not put it back meanwhile.
	r.fwdMu.Lock()
	r.forwards = nil
	r.fwdMu.Unlock()
	_ = r.update(func(m map[string]Entry) error {
		x := m["db.shop.doze"]
		x.Ports = nil
		m["db.shop.doze"] = x
		return nil
	})
	tbl := readPortTable(r.Path(), zone)
	var v [4]byte
	copy(v[:], lease.IP.To4())
	if _, ok := tbl.private(v, 5432); ok {
		t.Fatal("a mapping kept for another address was used")
	}
}
