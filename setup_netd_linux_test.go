//go:build linux

package names

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The daemon's unit runs the copy as the person who ran setup, after the
// interface it binds exists, and carries this build's version so check can
// tell an older one.
func TestTheLinuxDaemonUnitRunsAsThePersonAfterTheInterface(t *testing.T) {
	u := netdUnit("/home/me/.doze/names.json", 1000, 1000)
	for _, want := range []string{
		"User=1000\n", "Group=1000\n",
		"After=" + unitName + "\n",
		"ExecStart=" + netdPath + " " + helperArg + " /home/me/.doze/names.json\n",
		"Restart=always\n",
		netdStamp + "\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("the unit lacks %q:\n%s", want, u)
		}
	}
	path := filepath.Join(t.TempDir(), "doze-netd.service")
	if jobOutdated(path, netdStamp) {
		t.Error("no unit is not an old unit")
	}
	if err := os.WriteFile(path, []byte(u), 0o644); err != nil {
		t.Fatal(err)
	}
	if jobOutdated(path, netdStamp) {
		t.Error("this build's unit is current")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(u, netdStamp, "Environment=DOZE_NETD_VERSION=1", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if !jobOutdated(path, netdStamp) {
		t.Error("a unit naming an earlier version is old")
	}
}

// Where the zone can be routed, the privileged script installs the daemon
// beside the interface unit, and the uninstall takes both away.
func TestTheLinuxScriptInstallsTheDaemonWhereTheZoneIsRouted(t *testing.T) {
	script := privilegedScript(t)
	routed := canRouteDomain(detect(), dnsmasqPresent())
	for _, want := range []string{"cp -f ", netdPath, "> " + netdUnitPath, "systemctl enable --now " + netdUnitName} {
		if strings.Contains(script, want) != routed {
			t.Errorf("routed here = %v, yet the script's mention of %q = %v:\n%s", routed, want, !routed, script)
		}
	}
	var b strings.Builder
	if err := uninstall(Options{Out: &b, Print: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"systemctl disable --now " + netdUnitName, netdUnitPath, netdPath} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the uninstall lacks %q:\n%s", want, b.String())
		}
	}
}
