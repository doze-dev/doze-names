// doze-names sets a machine up for the .doze zone and reports on it. doze,
// doze-aws and doze-kafka each carry the same setup, so this program is not
// needed to use them: it is for looking at a machine, and for testing the
// library on its own.
package main

import (
	"fmt"
	"os"
	"sort"

	names "github.com/doze-dev/doze-names"
)

const usage = `usage: doze-names <command>

  setup       install what .doze needs on this machine (asks for sudo once)
  setup -n    print what setup would run, and change nothing
  check       report what is in place
  uninstall   remove what setup installed
  list        the names registered right now
`

func main() {
	names.Helper()

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = names.Install(names.Options{Print: len(os.Args) > 2 && os.Args[2] == "-n"})
	case "check":
		st := names.Check()
		fmt.Print(st)
		if !st.OK() {
			os.Exit(1)
		}
	case "uninstall":
		err = names.Uninstall(names.Options{})
	case "list":
		snap := names.Open(names.Home(), "doze-names").Snapshot()
		var hosts []string
		for h := range snap {
			if names.InZone(h) {
				hosts = append(hosts, h)
			}
		}
		sort.Strings(hosts)
		for _, h := range hosts {
			e := snap[h]
			fmt.Printf("%-32s %-16s %-10s pid %d\n", h, e.IP, e.Owner, e.PID)
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
