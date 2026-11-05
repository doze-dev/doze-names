//go:build darwin

package names

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheMacOSScriptsQuoteAndTouchOnlyWhatTheyAreAskedTo(t *testing.T) {
	s := routesScript([]string{"dev.acme.com", "api.acme.com", "other.example"}, []string{"dev.acme.com", "api.acme.com"}, []string{"old.acme.com"})
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
	// The whole set is Linux's concern; on macOS a route another stack keeps
	// is not rewritten.
	if strings.Contains(s, "other.example") {
		t.Errorf("a route not asked for was written:\n%s", s)
	}
	ca, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	if ts := trustScript(ca); !strings.Contains(ts, "add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain '") {
		t.Errorf("trust script = %q", ts)
	}
	// The root was trusted in the admin store, so its trust is removed by
	// file from the admin store (delete-certificate -t touches user trust
	// only), and then the certificate itself by hash.
	us := untrustScript(ca)
	if !strings.Contains(us, "remove-trusted-cert -d '"+ca.RootPath()+"'") || !strings.Contains(us, "delete-certificate -t -Z '"+ca.Fingerprint()+"'") {
		t.Errorf("untrust script = %q", us)
	}
	// Rotation keeps the old root by file and fingerprint so the same two
	// steps can remove its trust.
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
	if us := untrustFingerprintScript(again, old); !strings.Contains(us, "remove-trusted-cert -d '"+again.previousPath(old)+"'") {
		t.Errorf("a rotated-out root is untrusted by its kept file: %q", us)
	}
	if us := untrustFingerprintScript(again, "nope"); us != "" {
		t.Errorf("a fingerprint that is not one never reaches a script: %q", us)
	}
}

// The prompt names what the script does, and the script does only that:
// with two projects recorded under one home, the second project's setup
// writes its own route only, and its removal removes its own route only,
// never installing the first project's.
func TestTrustAndUntrustTouchOnlyTheRequestsRoutes(t *testing.T) {
	home := t.TempDir()
	one, two := t.TempDir(), t.TempDir()
	for _, dir := range []string{one, two} {
		if err := os.WriteFile(filepath.Join(dir, "doze.hcl"), []byte("app \"web\" {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Project one only ever ran doze up: its domain is recorded, not routed.
	if err := RecordDomains(home, one, []string{"dev.aud.example"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordDomains(home, two, []string{"api.aud.example"}); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	req := TrustRequest{Domains: []string{"api.aud.example"}, Home: home}
	if err := Trust(Options{Out: &out, Print: true}, req); err != nil {
		t.Fatal(err)
	}
	script := out.String()
	if !strings.Contains(script, "# route api.aud.example to doze") {
		t.Errorf("the prompt names the route:\n%s", script)
	}
	if !strings.Contains(script, "'/etc/resolver/api.aud.example'") {
		t.Errorf("the request's route is written:\n%s", script)
	}
	if strings.Contains(script, "dev.aud.example") {
		t.Errorf("another project's route was written by this project's prompt:\n%s", script)
	}
	out.Reset()
	if err := Untrust(Options{Out: &out, Print: true}, req); err != nil {
		t.Fatal(err)
	}
	script = out.String()
	if !strings.Contains(script, "rm -f '/etc/resolver/api.aud.example'") {
		t.Errorf("removal drops the request's route:\n%s", script)
	}
	if strings.Contains(script, "printf") || strings.Contains(script, "dev.aud.example") {
		t.Errorf("removal must install nothing:\n%s", script)
	}
	// --print changed nothing: both projects are still recorded.
	if c := Claimants(home, "dev.aud.example"); len(c) != 1 || c[0] != one {
		t.Errorf("project one's record = %v", c)
	}
	if c := Claimants(home, "api.aud.example"); len(c) != 1 || c[0] != two {
		t.Errorf("project two's record = %v", c)
	}
}
