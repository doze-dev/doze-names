package names

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The daemon that runs is the copy setup made, so a job from an older setup
// is reported until setup is run again; no job, or this build's, is not.
func TestCheckSeesADaemonFromAnOlderSetup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.plist")
	if netdOutdated(path) {
		t.Error("no job is not an old job")
	}
	current := launchdPlist("/Users/me/.doze/names.json", 501, 20)
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(current)
	if netdOutdated(path) {
		t.Error("this build's job is current")
	}
	write(strings.Replace(current, "<string>"+netdVersionDarwin+"</string>", "<string>2</string>", 1))
	if !netdOutdated(path) {
		t.Error("a job naming an earlier version is old")
	}
	// A job from before the version was recorded at all.
	from, to := strings.Index(current, "  <key>EnvironmentVariables</key>"), strings.Index(current, "  <key>ProgramArguments</key>")
	write(current[:from] + current[to:])
	if !netdOutdated(path) {
		t.Error("a job with no version is old")
	}
}
