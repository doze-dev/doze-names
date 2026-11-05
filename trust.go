package names

import (
	"fmt"
	"strings"
)

// Trusting a domain: the machine is told to ask this resolver for the
// domain (a route per domain), and the doze CA is trusted so https from the
// front door is believed. Both in one privileged script, one prompt, as the
// zone's setup is; both undone by Untrust. Opt-in: nothing here runs for a
// machine that declared no domain, and the CA is trusted only when a domain
// asked for https.

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
	// Home is where the routes record lives, updated after a removal.
	Home string
}

// TrustStatus reports, without privilege, what is in place for a request:
// one step per domain route, and one for the authority.
func TrustStatus(req TrustRequest) []Step {
	var steps []Step
	for _, d := range RouteDomains(req.Domains) {
		done, detail := domainRouted(d)
		steps = append(steps, Step{Name: "route " + d, Done: done, Detail: detail})
	}
	if req.CA != nil {
		done, detail := caTrusted(req.CA)
		steps = append(steps, Step{Name: "certificate authority", Done: done, Detail: detail})
	}
	for _, d := range req.Prune {
		steps = append(steps, Step{Name: "stale route " + d, Done: false, Detail: "no stack declares " + d + " any more; doze trust removes its route"})
	}
	return steps
}

// Trust installs the routes and trusts the authority, in one prompt. It is
// idempotent: what is in place already is left alone.
func Trust(o Options, req TrustRequest) error {
	steps := TrustStatus(req)
	var script []string
	var what []string
	for _, d := range RouteDomains(req.Domains) {
		if done, _ := domainRouted(d); !done {
			script = append(script, routeScript(d))
			what = append(what, d)
		}
	}
	if req.CA != nil {
		if done, _ := caTrusted(req.CA); !done {
			script = append(script, trustScript(req.CA))
			what = append(what, "the doze certificate authority")
		}
	}
	for _, d := range req.Prune {
		script = append(script, unrouteScript(d))
		what = append(what, "remove the stale route for "+d)
	}
	if len(script) == 0 {
		fmt.Fprintln(o.out(), "✓ already set up — nothing to do")
		return nil
	}
	_ = steps
	msg := "route " + strings.Join(what, ", ") + " to doze"
	if req.CA != nil {
		msg = "route the domains to doze and trust its certificate authority (it can sign only names declared on this machine)"
	}
	if err := runPrivileged(o, msg, strings.Join(script, "\n")); err != nil {
		return err
	}
	if o.Print {
		return nil
	}
	for _, d := range req.Prune {
		if routed, _ := domainRouted(d); !routed && req.Home != "" {
			_ = RouteRemoved(req.Home, d)
		}
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

// Untrust removes the routes and the authority's trust, in one prompt.
func Untrust(o Options, req TrustRequest) error {
	var script []string
	for _, d := range RouteDomains(req.Domains) {
		script = append(script, unrouteScript(d))
	}
	if req.CA != nil {
		script = append(script, untrustScript(req.CA))
	}
	if len(script) == 0 {
		return nil
	}
	if err := runPrivileged(o, "remove the domain routes and the certificate authority's trust", strings.Join(script, "\n")); err != nil {
		return err
	}
	if !o.Print {
		if req.Home != "" {
			for _, d := range RouteDomains(req.Domains) {
				_ = RouteRemoved(req.Home, d)
			}
		}
		fmt.Fprintln(o.out(), "✓ removed")
	}
	return nil
}
