//go:build darwin

package names

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTheMacOSScriptsQuoteAndRestateRoutes(t *testing.T) {
	s := routesScript([]string{"dev.acme.com", "api.acme.com"}, []string{"old.acme.com"})
	for _, want := range []string{
		"mkdir -p /etc/resolver",
		"printf 'nameserver 127.0.0.1\\nport 5323\\n' > '/etc/resolver/dev.acme.com'",
		"> '/etc/resolver/api.acme.com'",
		"rm -f '/etc/resolver/old.acme.com'",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("routes script lacks %q:\n%s", want, s)
		}
	}
	ca, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	if ts := trustScript(ca); !strings.Contains(ts, "add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain '") {
		t.Errorf("trust script = %q", ts)
	}
	if us := untrustScript(ca); !strings.Contains(us, "delete-certificate -t -Z '"+ca.Fingerprint()+"'") {
		t.Errorf("untrust script = %q", us)
	}
	// Rotation remembers the old root so a prompt can stop trusting it.
	old := ca.Fingerprint()
	if err := ca.Rotate(); err != nil {
		t.Fatal(err)
	}
	if p := ca.Previous(); len(p) != 1 || p[0] != old {
		t.Errorf("previous = %v, want the old fingerprint", p)
	}
	again, ok := OpenCA(ca.dir)
	if !ok || len(again.Previous()) != 1 {
		t.Error("the rotated-out fingerprint is kept on disk")
	}
	if u := Untrust; u == nil {
		t.Fatal("unreachable")
	}
}
