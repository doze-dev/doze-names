package names

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Trusting a domain: the machine is told to ask this resolver for the
// domain (a route per domain), and the doze CA is trusted so https from the
// front door is believed. Both in one privileged script, one prompt, as the
// zone's setup is; both undone by Untrust. Opt-in: nothing here runs for a
// machine that declared no domain, and the CA is trusted only when a domain
// asked for https.
//
// The prompt says what the script does, and the script does only that: on
// macOS the files written are the request's own domains, and the files
// removed are the stale ones; on Linux the link's domain list is one
// setting, so every change restates every route that should exist, and the
// prompt says so.

// TrustRequest is what to set up.
type TrustRequest struct {
	// Domains are the declared names; wildcards are folded onto the name
	// under them (RouteDomains).
	Domains []string
	// CA is the authority to trust; nil trusts none.
	CA *CA
	// Prune are routed domains nobody declares any more (StaleRoutes); they
	// are removed in the same prompt.
	Prune []string
	// Home is where the routes record lives: the whole set of routes the
	// machine should keep is read from it, and it is updated after a run.
	Home string
	// UntrustAll, for Untrust, removes every doze authority the machine
	// trusts, named or not: the last project is leaving, and a root whose
	// files are gone must not stay trusted.
	UntrustAll bool
}

// routeSet is every route the machine should keep after a run: the
// request's domains, plus what other projects recorded, minus the pruned.
func (req TrustRequest) routeSet() []string {
	keep := map[string]bool{}
	for _, d := range RouteDomains(req.Domains) {
		keep[d] = true
	}
	if req.Home != "" {
		for d, dirs := range readRoutes(req.Home) {
			if declared(dirs) {
				keep[d] = true
			}
		}
	}
	for _, d := range req.Prune {
		delete(keep, d)
	}
	var out []string
	for d := range keep {
		out = append(out, d)
	}
	sortStrings(out)
	return out
}

// TrustStatus reports, without privilege, what is in place for a request:
// one step per domain route, one for the authority, one per stale route.
func TrustStatus(req TrustRequest) []Step {
	var steps []Step
	for _, d := range RouteDomains(req.Domains) {
		done, detail := domainRouted(d)
		steps = append(steps, Step{Name: "route " + d, Done: done, Detail: detail})
	}
	if req.CA != nil {
		done, detail := caTrusted(req.CA)
		steps = append(steps, Step{Name: "certificate authority", Done: done, Detail: detail})
		for _, fp := range req.CA.previous {
			if trusted, _ := fingerprintTrusted(req.CA, fp); trusted {
				steps = append(steps, Step{Name: "old authority " + shortFP(fp), Done: false, Detail: "a rotated-out authority is still trusted; doze trust removes it"})
			}
		}
	}
	for _, d := range req.Prune {
		steps = append(steps, Step{Name: "stale route " + d, Done: false, Detail: "no stack declares " + d + " any more; doze trust removes its route"})
	}
	return steps
}

// TrustSupported says this platform has domain routes and a trust store.
func TrustSupported() bool { return platformTrust() == nil }

// Trust installs the routes and trusts the authority, in one prompt. It is
// idempotent: what is in place already is left alone, and so is a route
// file that is someone else's.
func Trust(o Options, req TrustRequest) error {
	if err := platformTrust(); err != nil {
		return err
	}
	var script, what []string
	var missing, foreign []string
	for _, d := range RouteDomains(req.Domains) {
		if routeForeign(d) {
			foreign = append(foreign, d)
			continue
		}
		if done, _ := domainRouted(d); !done {
			missing = append(missing, d)
		}
	}
	for _, d := range foreign {
		_, detail := domainRouted(d)
		fmt.Fprintf(o.out(), "✗ route %s · %s\n", d, detail)
	}
	if len(missing) > 0 || len(req.Prune) > 0 {
		if s := routesScript(req.routeSet(), missing, req.Prune); s != "" {
			script = append(script, s)
		}
		if len(missing) > 0 {
			what = append(what, "route "+strings.Join(missing, ", ")+" to doze")
		}
		if len(req.Prune) > 0 {
			what = append(what, "remove the stale route for "+strings.Join(req.Prune, ", "))
		}
		if others := othersIn(req.routeSet(), missing); len(others) > 0 && restatesRoutes() {
			what = append(what, "restate the routes other stacks keep ("+strings.Join(others, ", ")+")")
		}
	}
	if req.CA != nil {
		for _, fp := range req.CA.previous {
			if trusted, _ := fingerprintTrusted(req.CA, fp); trusted {
				script = append(script, untrustFingerprintScript(req.CA, fp))
				what = append(what, "stop trusting a rotated-out authority")
			}
		}
		if done, _ := caTrusted(req.CA); !done {
			script = append(script, trustScript(req.CA))
			what = append(what, "trust the doze certificate authority for TLS on this machine (its key stays in "+req.CA.dir+"; anyone with that key could sign any name for this machine)")
		}
	}
	if len(script) == 0 {
		fmt.Fprintln(o.out(), "✓ already set up — nothing to do")
		return nil
	}
	if err := runPrivileged(o, strings.Join(what, "; "), strings.Join(script, "\n")); err != nil {
		return err
	}
	if o.Print {
		return nil
	}
	if req.Home != "" {
		for _, d := range req.Prune {
			if routed, _ := domainRouted(d); !routed {
				_ = RouteRemoved(req.Home, d)
			}
		}
	}
	if req.CA != nil {
		_ = req.CA.forgetUntrustedPrevious()
	}
	req.Prune = nil
	for _, st := range TrustStatus(req) {
		mark := "✗"
		if st.Done {
			mark = "✓"
		}
		fmt.Fprintf(o.out(), "%s %s · %s\n", mark, st.Name, st.Detail)
	}
	return nil
}

// othersIn are the routes in set that are not in mine.
func othersIn(set, mine []string) []string {
	isMine := map[string]bool{}
	for _, d := range mine {
		isMine[d] = true
	}
	var out []string
	for _, d := range set {
		if !isMine[d] {
			out = append(out, d)
		}
	}
	return out
}

// restatesRoutes says the platform writes the whole route set on every
// change (Linux), so the prompt must mention the others.
func restatesRoutes() bool { return routesScript([]string{"a.example.com"}, nil, nil) != "" }

// Untrust removes the request's routes and, when CA is set, every trust of
// the authority (the current root and any rotated out), in one prompt; with
// UntrustAll, every doze authority the machine holds. Routes other projects
// still declare are kept.
func Untrust(o Options, req TrustRequest) error {
	if err := platformTrust(); err != nil {
		return err
	}
	var script, what []string
	removing := RouteDomains(req.Domains)
	if len(removing) > 0 {
		keep := TrustRequest{Home: req.Home, Prune: removing}.routeSet()
		if s := routesScript(keep, nil, removing); s != "" {
			script = append(script, s)
			what = append(what, "remove the route for "+strings.Join(removing, ", "))
		}
	}
	if req.CA != nil {
		script = append(script, untrustScript(req.CA))
		for _, fp := range req.CA.previous {
			script = append(script, untrustFingerprintScript(req.CA, fp))
		}
		what = append(what, "stop trusting the doze certificate authority")
	}
	if req.UntrustAll {
		if s := untrustUnknownScript(); len(s) > 0 {
			script = append(script, s...)
			if req.CA == nil {
				what = append(what, "stop trusting every doze certificate authority")
			}
		}
	}
	script = nonEmpty(script)
	if len(script) == 0 {
		fmt.Fprintln(o.out(), "nothing to remove")
		return nil
	}
	if err := runPrivileged(o, strings.Join(what, "; "), strings.Join(script, "\n")); err != nil {
		return err
	}
	if o.Print {
		return nil
	}
	if req.Home != "" {
		for _, d := range removing {
			_ = RouteRemoved(req.Home, d)
		}
	}
	fmt.Fprintln(o.out(), "✓ removed")
	return nil
}

func nonEmpty(lines []string) []string {
	out := lines[:0:0]
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// ErrNoTrust says this platform has no domain routes or trust store yet.
var ErrNoTrust = errors.New("domains and https are not set up on this platform yet")

// cleanupScript is what dns-setup --uninstall adds for domains: every
// recorded route removed, and every doze authority's trust, whether or not
// the files that made it can still be read, so nothing of doze is left
// pointing at a resolver that will not come back.
func cleanupScript(home string) []string {
	var out []string
	if routes := RecordedRoutes(home); len(routes) > 0 {
		out = append(out, uninstallRoutesScript(routes))
	}
	if ca, err := ProbeCA(CADir(home)); ca != nil && err == nil {
		out = append(out, untrustScript(ca))
		for _, fp := range ca.previous {
			out = append(out, untrustFingerprintScript(ca, fp))
		}
	}
	out = append(out, untrustUnknownScript()...)
	return nonEmpty(out)
}

// cleanupAfter removes what the person owns once the privileged part ran:
// the authority's files and the routes record.
func cleanupAfter(home string) {
	_ = os.RemoveAll(CADir(home))
	_ = os.Remove(routesPath(home))
	_ = os.Remove(routesPath(home) + ".lock")
}
