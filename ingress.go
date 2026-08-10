package names

// The shared HTTP front door.
//
// A name should mean one URL — http://aws.doze, not http://aws.doze:4566 in one
// mode and port-less in another. Serving that from the name's own address does
// not work: macOS refuses a privileged port on a SPECIFIC address and allows it
// only on the wildcard (measured — :80 and 0.0.0.0:80 bind, 127.0.0.2:80 does
// not). So port 80 has to come from one wildcard listener shared by every doze
// binary, routing by Host header.
//
// Which is the resolver's problem again, so it gets the resolver's answer:
// first-come binding, take-over when the holder exits, and the holder serving
// every peer's routes rather than only its own. The routes live in the same
// registry as the names, so one file, one lock, and one liveness rule cover
// both — a process that dies stops answering DNS and stops being proxied to at
// the same moment.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// IngressAddr is the shared front door. The wildcard is not a detail: it is the
// only form macOS will bind unprivileged.
const IngressAddr = ":80"

// Route publishes where this name's traffic should go — "127.0.0.2:4566", say.
// Until a name has a route the front door does not answer for it, so a service
// that only wants DNS can leave it unset.
func (l *Lease) Route(target string) error {
	if l == nil || l.reg == nil {
		return nil
	}
	return l.reg.update(func(m map[string]Entry) error {
		e, ok := m[l.Name.Host]
		if !ok || e.PID != l.reg.pid {
			return fmt.Errorf("%s is not held by this process", l.Name.Host)
		}
		e.Target = target
		m[l.Name.Host] = e
		return nil
	})
}

// routeFor returns the backend for a Host header, or "" if this machine does
// not front that name.
func (r *Registry) routeFor(host string) string {
	// A Host header may carry a port; the name is what matters.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !InZone(host) {
		return ""
	}
	return r.Snapshot()[normalize(host)].Target
}

// Ingress is the shared front door for as long as this process holds it.
type Ingress struct {
	cancel context.CancelFunc
	done   chan struct{}
	bound  chan struct{}
}

// ServeIngress fronts every peer's routed names on the shared port, taking it
// if free and waiting for it if a peer holds it. Like Serve, it never fails:
// standing by is the normal case for all but one process, and the names work
// either way because whoever holds the port reads the same registry.
func ServeIngress(ctx context.Context, r *Registry, logf func(string, ...any)) *Ingress {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(ctx)
	in := &Ingress{cancel: cancel, done: make(chan struct{}), bound: make(chan struct{})}

	go func() {
		defer close(in.done)
		var announced bool
		for {
			ln, err := net.Listen("tcp", IngressAddr)
			switch {
			case err == nil:
				select {
				case <-in.bound:
				default:
					close(in.bound)
				}
				logf("names: fronting %s on %s", Suffix, IngressAddr)
				announced = false
				srv := &http.Server{Handler: proxy(r)}
				go func() { <-ctx.Done(); _ = srv.Close() }()
				_ = srv.Serve(ln)
				if ctx.Err() != nil {
					return
				}
			case isAddrInUse(err):
				if !announced {
					logf("names: a peer is already fronting %s; standing by", Suffix)
					announced = true
				}
			default:
				if !announced {
					// On Linux this is the sysctl not being applied. Say so
					// rather than leaving a bare EACCES.
					logf("names: cannot bind %s (%v); names will need their port", IngressAddr, err)
					announced = true
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryInterval):
			}
		}
	}()
	return in
}

// Bound blocks until this process holds the port, or ctx ends.
func (in *Ingress) Bound(ctx context.Context) bool {
	select {
	case <-in.bound:
		return true
	case <-ctx.Done():
		return false
	}
}

// Close stops fronting and releases the port for a peer to take.
func (in *Ingress) Close() {
	if in == nil {
		return
	}
	in.cancel()
	<-in.done
}

// proxy routes by Host header to whichever peer registered that name.
func proxy(r *Registry) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			target := r.routeFor(pr.In.Host)
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = target
			// Preserve the original Host. doze-aws builds the URLs it hands
			// back from it — a queue created through aws.doze must report an
			// aws.doze URL, not the loopback address it was proxied to.
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.routeFor(req.Host) == "" {
			// Not ours. Say which names this machine does front, because the
			// usual cause is a service that is not running.
			http.Error(w, "no doze service is fronting "+hostOnly(req.Host)+
				"\n\nfronted here:\n"+strings.Join(routed(r), "\n"), http.StatusNotFound)
			return
		}
		rp.ServeHTTP(w, req)
	})
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// routed lists the names currently fronted, for the 404 body.
func routed(r *Registry) []string {
	var out []string
	for host, e := range r.Snapshot() {
		if e.Target != "" {
			out = append(out, "  http://"+host+"  →  "+e.Target+"  ("+e.Owner+")")
		}
	}
	if len(out) == 0 {
		out = append(out, "  (nothing — no doze service has registered a route)")
	}
	return out
}

// URLFor is the URL a name is reachable at: port-less when the front door is
// up, and with the backend's port when it is not, so callers can print
// something that actually works either way.
func (r *Registry) URLFor(host string) string {
	e, ok := r.Snapshot()[normalize(host)]
	if !ok || e.Target == "" {
		return ""
	}
	if l, err := net.Listen("tcp", IngressAddr); err == nil {
		// Nothing is fronting: the port is free, so the name alone will not
		// reach anything.
		_ = l.Close()
		if _, port, err := net.SplitHostPort(e.Target); err == nil {
			return "http://" + host + ":" + port
		}
	}
	return "http://" + host
}
