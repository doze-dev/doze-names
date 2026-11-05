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
// The routes are written as a whole: on Linux the link's domain list is one
// setting, so every change restates every route that should exist; on
// macOS each route is a file, and the same whole-set view says which to
// write and which to remove.

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
			if trusted, _ := fingerprintTrusted(fp); trusted {
				steps = append(steps, Step{Name: "old authority " + fp[:12], Done: false, Detail: "a rotated-out authority is still trusted; doze trust removes it"})
			}
		}
	}
	for _, d := range req.Prune {
		steps = append(steps, Step{Name: "stale route " + d, Done: false, Detail: "no stack declares " + d + " any more; doze trust removes its route"})
	}
	return steps
}

// Trust installs the routes and trusts the authority, in one prompt. It is
// idempotent: what is in place already is left alone.
func Trust(o Options, req TrustRequest) error {
	if err := platformTrust(); err != nil {
		return err
	}
	var script, what []string
	var missing []string
	for _, d := range RouteDomains(req.Domains) {
		if done, _ := domainRouted(d); !done {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 || len(req.Prune) > 0 {
		script = append(script, routesScript(req.routeSet(), req.Prune))
		if len(missing) > 0 {
			what = append(what, "route "+strings.Join(missing, ", ")+" to doze")
		}
		if len(req.Prune) > 0 {
			what = append(what, "remove the stale route for "+strings.Join(req.Prune, ", "))
		}
	}
	if req.CA != nil {
		for _, fp := range req.CA.previous {
			if trusted, _ := fingerprintTrusted(fp); trusted {
				script = append(script, untrustFingerprintScript(fp))
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

// Untrust removes the request's routes and, when CA is set, every trust of
// the authority (the current root and any rotated out), in one prompt.
// Routes other projects still declare are kept.
func Untrust(o Options, req TrustRequest) error {
	if err := platformTrust(); err != nil {
		return err
	}
	var script []string
	removing := RouteDomains(req.Domains)
	if len(removing) > 0 {
		keep := TrustRequest{Home: req.Home, Prune: removing}.routeSet()
		script = append(script, routesScript(keep, removing))
	}
	if req.CA != nil {
		script = append(script, untrustScript(req.CA))
		for _, fp := range req.CA.previous {
			script = append(script, untrustFingerprintScript(fp))
		}
	}
	if len(script) == 0 {
		fmt.Fprintln(o.out(), "nothing to remove")
		return nil
	}
	if err := runPrivileged(o, "remove the domain routes and the certificate authority's trust", strings.Join(script, "\n")); err != nil {
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

// ErrNoTrust says this platform has no domain routes or trust store yet.
var ErrNoTrust = errors.New("domains and https are not set up on this platform yet")

// cleanupScript is what dns-setup --uninstall adds for domains: every
// recorded route removed, and the authority's trust, so nothing of doze is
// left pointing at a resolver that will not come back.
func cleanupScript(home string) []string {
	var out []string
	if routes := RecordedRoutes(home); len(routes) > 0 {
		out = append(out, routesScript(nil, routes))
	}
	if ca, ok := OpenCA(CADir(home)); ok {
		out = append(out, untrustScript(ca))
		for _, fp := range ca.previous {
			out = append(out, untrustFingerprintScript(fp))
		}
	}
	return out
}

// cleanupAfter removes what the person owns once the privileged part ran:
// the authority's files and the routes record.
func cleanupAfter(home string) {
	_ = os.RemoveAll(CADir(home))
	_ = os.Remove(routesPath(home))
	_ = os.Remove(routesPath(home) + ".lock")
}
