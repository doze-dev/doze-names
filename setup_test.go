package names

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const otherPeoplesHosts = `##
# Host Database
##
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost

# Added by Docker Desktop
192.168.1.10 host.docker.internal
`

func TestHostsBlockRoundTrip(t *testing.T) {
	want := apexHostsBlock()

	added := replaceHostsBlock(otherPeoplesHosts, want)
	if !strings.Contains(added, want) {
		t.Fatal("block was not added")
	}
	// Everything that was there before must survive untouched. This file
	// belongs to the user and to several other tools; the only lines that are
	// ours are the ones between our markers.
	for _, line := range strings.Split(strings.TrimSpace(otherPeoplesHosts), "\n") {
		if !strings.Contains(added, line) {
			t.Errorf("lost a pre-existing line: %q", line)
		}
	}

	// Idempotent: running setup again must not grow the file. DDEV once
	// appended to /etc/hosts on every run and users ended up with enormous
	// ones, which is the failure this test exists to make impossible.
	twice := replaceHostsBlock(added, want)
	if twice != added {
		t.Errorf("second write changed the file:\n--- once ---\n%s\n--- twice ---\n%s", added, twice)
	}
	if strings.Count(twice, hostsBegin) != 1 {
		t.Errorf("block appears %d times, want 1", strings.Count(twice, hostsBegin))
	}

	// And removal leaves the original behind.
	removed := replaceHostsBlock(added, "")
	if strings.Contains(removed, hostsBegin) || strings.Contains(removed, "aws."+Suffix) {
		t.Errorf("uninstall left something behind:\n%s", removed)
	}
	for _, line := range strings.Split(strings.TrimSpace(otherPeoplesHosts), "\n") {
		if !strings.Contains(removed, line) {
			t.Errorf("uninstall lost a pre-existing line: %q", line)
		}
	}
}

func TestHostsBlockSurvivesAMissingEndMarker(t *testing.T) {
	// Someone hand-edited the file and deleted the end marker. Truncating to
	// the end of the file would eat whatever came after — including entries
	// another tool depends on.
	damaged := otherPeoplesHosts + hostsBegin + "\n127.0.0.2\taws.doze\n" +
		"# Added by something else\n10.0.0.5 important.internal\n"

	fixed := replaceHostsBlock(damaged, apexHostsBlock())
	if !strings.Contains(fixed, "10.0.0.5 important.internal") {
		t.Error("a damaged block took an unrelated entry with it")
	}
}

func TestHostsBlockOnAnEmptyFile(t *testing.T) {
	out := replaceHostsBlock("", apexHostsBlock())
	if !strings.Contains(out, "aws."+Suffix) {
		t.Fatal("block not written to an empty file")
	}
	if replaceHostsBlock(out, apexHostsBlock()) != out {
		t.Error("not idempotent on a file that started empty")
	}
}

func TestApexBlockIsByteStable(t *testing.T) {
	// Check compares the file against this string, so an unstable render (map
	// iteration order, say) would report "not installed" at random.
	first := apexHostsBlock()
	for i := 0; i < 20; i++ {
		if apexHostsBlock() != first {
			t.Fatal("apexHostsBlock is not deterministic")
		}
	}
	for _, svc := range apexServices() {
		if !strings.Contains(first, apexIP[svc]) || !strings.Contains(first, Apex(svc).Host) {
			t.Errorf("block omits %s", svc)
		}
	}
}

func TestHostsBlockInstalledReadsTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	orig := hostsPath
	hostsPath = path
	t.Cleanup(func() { hostsPath = orig })

	if err := os.WriteFile(path, []byte(otherPeoplesHosts), 0o644); err != nil {
		t.Fatal(err)
	}
	if hostsBlockInstalled() {
		t.Error("reported installed before anything was written")
	}
	if err := os.WriteFile(path, []byte(replaceHostsBlock(otherPeoplesHosts, apexHostsBlock())), 0o644); err != nil {
		t.Fatal(err)
	}
	if !hostsBlockInstalled() {
		t.Error("reported not installed after writing the block")
	}
}

func TestShellQuote(t *testing.T) {
	// The script is assembled by concatenation and handed to a shell, so a
	// quote in any value must not be able to end the argument.
	for _, in := range []string{"plain", "with 'quotes'", "$(whoami)", "a\nb"} {
		got := shellQuote(in)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("shellQuote(%q) = %s, not single-quoted", in, got)
		}
	}
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("shellQuote(it's) = %s", got)
	}
}
