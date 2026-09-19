//go:build linux

package names

// The privileged script, asserted as text.
//
// install() with Print set writes the script instead of running it — the same
// path `doze-aws dns-setup --print` and the "do it by hand" fallback use — so
// what a root shell would execute can be checked without a root shell.

import (
	"bytes"
	"strings"
	"testing"
)

func privilegedScript(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	if err := install(Options{Out: &b, Print: true}); err != nil {
		t.Fatalf("building the script: %v", err)
	}
	if b.Len() == 0 {
		t.Fatal("no script: every assertion below would pass vacuously")
	}
	return b.String()
}

// `sysctl --system` reapplies every sysctl.d file on the machine to set one
// key. Inside a container most of /proc/sys is read-only, so it fails on keys
// that have nothing to do with doze — kernel.sysrq, kernel.core_uses_pid — and
// `set -e` aborts before the hosts block is written. The whole install failed
// for the sake of a setting nobody asked about.
func TestTheSysctlAppliesOnlyOurOwnFile(t *testing.T) {
	script := privilegedScript(t)

	if strings.Contains(script, "--system") {
		t.Errorf("the script still calls `sysctl --system`:\n%s\n"+
			"  That applies every sysctl.d file on the machine, not ours. In a "+
			"container it fails\n  on unrelated read-only keys and takes the "+
			"hosts block down with it.", script)
	}
	if !strings.Contains(script, "sysctl -q -p "+sysctlPath) {
		t.Errorf("the script does not apply %s by name:\n%s", sysctlPath, script)
	}
}

// The key is the one optional step here: it lets an UNPRIVILEGED process bind
// :80, and a container runs as root and can bind it anyway. Where it cannot be
// set, ingress logs "names will need their port", Status reports the step as
// not done, and names still resolve. Failing the install over it costs the
// hosts block, which is the part that matters.
func TestAFailedSysctlDoesNotAbortTheInstall(t *testing.T) {
	script := privilegedScript(t)

	var sysctlLine string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "sysctl ") {
			sysctlLine = line
			break
		}
	}
	if sysctlLine == "" {
		t.Fatalf("no sysctl line in the script:\n%s", script)
	}
	if !strings.HasSuffix(sysctlLine, "|| true") {
		t.Errorf("the sysctl line is fatal under `set -e`:\n  %s\n"+
			"  It has to tolerate failing: the key is read-only in a container "+
			"and unnecessary\n  there, and everything downstream already copes "+
			"with it not being set.", sysctlLine)
	}
	// And the ordering the tolerance exists to protect.
	// Matched on the redirection, not the path: the captured output opens with
	// a "# apply the sysctl, write the /etc/hosts block" comment, so the bare
	// path appears before either command and finds the wrong line.
	if i, j := strings.Index(script, "sysctl -q -p"), strings.Index(script, "> "+hostsPath); i < 0 || j < 0 || i > j {
		t.Errorf("the hosts block is not written after the sysctl:\n%s\n"+
			"  The sysctl is allowed to fail so that what follows still runs; "+
			"if nothing follows\n  it, the tolerance is pointless.", script)
	}
}
