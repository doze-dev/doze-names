package names

import (
	"net"
	"testing"
)

func TestDisabledHonoursDOZE_ZONE(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"", false}, {"on", false}, {"1", false}, {"yes", false},
		{"off", true}, {"OFF", true}, {" off ", true}, {"0", true}, {"false", true}, {"no", true},
	} {
		t.Setenv(EnvZone, tc.val)
		if got := Disabled(); got != tc.want {
			t.Errorf("DOZE_ZONE=%q: Disabled() = %v, want %v", tc.val, got, tc.want)
		}
	}
}

func TestReachableOnlyWhenSomethingAnswers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on loopback")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if !Reachable("127.0.0.1", port) {
		t.Error("an address with a listener reported unreachable")
	}
	ln.Close()
	if Reachable("127.0.0.1", port) {
		t.Error("an address with nothing listening reported reachable")
	}
}
