package names

// Machine setup: the one-time, privileged work that makes .doze resolve.
//
// Any binary can run it and running it twice is a no-op, so `doze dns-setup`,
// `doze-aws dns-setup` and `doze-kafka dns-setup` are the same command —
// whichever one you happen to have installed can set the machine up.
//
// Everything privileged happens in a single shell script under one sudo
// prompt, and every step is reported independently by Check so a partial
// install is visible rather than mysterious.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// hostsPath is the file the apex block is written into. A variable so tests
// can point it somewhere harmless — nothing here should ever touch the real
// /etc/hosts during a test run.
var hostsPath = "/etc/hosts"

// The apex block is bounded by markers so it can be rewritten or removed
// exactly, without touching a line anyone else owns. DDEV once decided it had
// no internet connection and appended to users' /etc/hosts until it was
// enormous; a marked, idempotently-replaced block cannot do that no matter how
// many times it runs.
const (
	hostsBegin = "# BEGIN doze — managed, safe to delete"
	hostsEnd   = "# END doze"
)

// Step is one component of the setup, reported on its own so a half-finished
// install says which half.
type Step struct {
	Name   string
	Done   bool
	Detail string
}

// Status is what Check found.
type Status struct {
	Platform string
	Steps    []Step
}

// OK reports whether every step is in place.
func (s Status) OK() bool {
	for _, st := range s.Steps {
		if !st.Done {
			return false
		}
	}
	return len(s.Steps) > 0
}

// String renders the status as one line per step.
func (s Status) String() string {
	var b strings.Builder
	for _, st := range s.Steps {
		mark := "✗"
		if st.Done {
			mark = "✓"
		}
		fmt.Fprintf(&b, "%s %-22s %s\n", mark, st.Name, st.Detail)
	}
	return b.String()
}

// Options configures a setup run.
type Options struct {
	// Out receives progress. Defaults to os.Stdout.
	Out io.Writer
	// Print writes the privileged script to Out instead of running it, for
	// anyone who would rather paste it themselves than hand a tool sudo.
	Print bool
}

func (o Options) out() io.Writer {
	if o.Out == nil {
		return os.Stdout
	}
	return o.Out
}

// Check reports what is in place without needing any privilege.
func Check() Status { return check() }

// Install performs the one-time machine setup. It is idempotent.
func Install(o Options) error { return install(o) }

// Uninstall removes everything Install wrote.
func Uninstall(o Options) error { return uninstall(o) }

// apexHostsBlock renders the managed block: every reserved apex name at its
// fixed address. It is deliberately static — it does not reflect what is
// running, so it never needs rewriting as services come and go, and a name
// whose service is stopped resolves to a refused connection rather than to
// "no such host".
func apexHostsBlock() string {
	var b strings.Builder
	b.WriteString(hostsBegin + "\n")
	// Sorted by address so the block is byte-stable across runs; an unstable
	// block would show up as a spurious diff every time Check compares.
	for _, svc := range apexServices() {
		fmt.Fprintf(&b, "%s\t%s\n", apexIP[svc], Apex(svc).Host)
	}
	b.WriteString(hostsEnd + "\n")
	return b.String()
}

// apexServices returns the reserved service names in a stable order.
func apexServices() []string {
	out := make([]string, 0, len(apexIP))
	for svc := range apexIP {
		out = append(out, svc)
	}
	// Insertion sort by address: the table is tiny and this avoids importing
	// sort for one call.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && apexIP[out[j]] < apexIP[out[j-1]]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// replaceHostsBlock returns hosts with the managed block replaced by want, or
// appended if it was not there. want may be empty to remove the block.
//
// Everything outside the markers is preserved byte for byte: this file belongs
// to the user and to several other tools, and the only lines that are ours are
// the ones between our own markers.
func replaceHostsBlock(hosts, want string) string {
	start := strings.Index(hosts, hostsBegin)
	if start < 0 {
		if want == "" {
			return hosts
		}
		if hosts != "" && !strings.HasSuffix(hosts, "\n") {
			hosts += "\n"
		}
		return hosts + "\n" + want
	}
	// Index into the tail is RELATIVE to start; every use below is absolute, so
	// it has to be rebased. Getting this wrong splices the file back together
	// at the wrong offset and corrupts lines that were never ours.
	var end int
	if rel := strings.Index(hosts[start:], hostsEnd); rel < 0 {
		// An end marker that went missing — truncating to the end of the file
		// would delete whatever followed, so treat the block as just its first
		// line and leave the rest alone.
		end = start + len(hostsBegin)
	} else {
		end = start + rel + len(hostsEnd)
		// Take the newline that ends the marker line too, if it is there.
		if end < len(hosts) && hosts[end] == '\n' {
			end++
		}
	}
	head, tail := hosts[:start], hosts[end:]
	if want == "" {
		// Collapse the blank line the block was separated by.
		head = strings.TrimSuffix(head, "\n")
		if head != "" && !strings.HasSuffix(head, "\n") {
			head += "\n"
		}
		return head + tail
	}
	return head + want + tail
}

// hostsBlockInstalled reports whether the current file already carries exactly
// the block we would write.
func hostsBlockInstalled() bool {
	raw, err := os.ReadFile(hostsPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), apexHostsBlock())
}

// runPrivileged executes script under sudo as a single prompt, or prints it
// when Options.Print is set. One prompt matters: a setup that asks three times
// trains people to type their password without reading what it is for.
func runPrivileged(o Options, what, script string) error {
	if o.Print {
		fmt.Fprintf(o.out(), "# %s\n%s", what, pasteable(script))
		return nil
	}
	fmt.Fprintf(o.out(), "doze needs sudo once: %s\n", what)
	c := exec.Command("sudo", "sh", "-c", script)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, o.out(), os.Stderr
	if err := c.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nthe privileged step failed. To do it by hand:\n\n%s", pasteable(script))
		return fmt.Errorf("setup: %w", err)
	}
	return nil
}

// pasteable renders the script as something a person can actually paste.
//
// Not `sudo sh -c '<script>'`: the script contains single quotes of its own —
// heredoc delimiters and printf arguments — and the first of them ends the
// quoting, so the pasted command breaks in a way that is tedious to diagnose.
// Feeding it on stdin through a quoted heredoc sidesteps quoting entirely, and
// nests correctly with the heredocs already inside the script because the
// delimiters differ.
func pasteable(script string) string {
	const delim = "DOZE_SETUP"
	return "sudo sh <<'" + delim + "'\n" + strings.TrimRight(script, "\n") + "\n" + delim + "\n"
}

// shellQuote renders s for safe inclusion in a single-quoted shell heredoc
// argument. The inputs here are our own constants, but the script is assembled
// by string concatenation and handed to a shell, so quoting is not optional.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
