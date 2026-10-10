package names

import (
	"fmt"
	"os"
)

// helperArg is the first argument that makes a doze program run as the
// network daemon and nothing else.
const helperArg = "__doze-netd"

// Helper must be the first thing main does in every doze program. Setup
// installs a copy of the program that ran it as the macOS network daemon, and
// launchd starts that copy with helperArg; Helper is where it turns into the
// daemon. For any other invocation it returns at once.
func Helper() {
	if len(os.Args) < 2 || os.Args[1] != helperArg {
		return
	}
	if err := runNetd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
