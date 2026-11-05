package names

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Forwarding. A query reaches this resolver for a domain only because the
// machine was told to send that domain here (a route in /etc/resolver, or
// resolved's). When the stack that claimed the domain is down, the honest
// answer is whatever the internet says: dev.acme.com may be a real host,
// and a laptop that cannot reach it whenever doze is not running is a
// trap. So an unregistered name outside the doze zone is forwarded to the
// system's own upstream servers and their answer relayed. Nothing in the
// doze zone is ever forwarded: a typo there is NXDOMAIN, as before.

const (
	upstreamRefresh = time.Minute
	upstreamTimeout = 4 * time.Second
)

// upstreams is the list, found lazily and refreshed now and then.
type upstreams struct {
	mu    sync.Mutex
	at    time.Time
	addrs []string
}

var upstream = &upstreams{}

// find reads the system's resolvers, leaving out this resolver and the
// loopback stubs that would send the query straight back here.
func (u *upstreams) find() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if time.Since(u.at) < upstreamRefresh && u.addrs != nil {
		return u.addrs
	}
	var out []string
	switch runtime.GOOS {
	case "darwin":
		out = scutilResolvers()
	default:
		out = resolvConfServers("/run/systemd/resolve/resolv.conf")
		if len(out) == 0 {
			out = resolvConfServers("/etc/resolv.conf")
		}
	}
	u.at, u.addrs = time.Now(), out
	return out
}

// own says an address is one of ours or a local stub that would loop.
func own(ip string) bool {
	switch ip {
	case "127.0.0.1", "::1", "127.0.0.53", "127.0.0.54", resolverIP:
		return true
	}
	return false
}

// scutilResolvers reads `scutil --dns`: the nameservers of every resolver
// block that has no domain of its own, which is what the machine asks for
// everything else.
func scutilResolvers() []string {
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	var servers []string
	seen := map[string]bool{}
	scoped := false
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(f, "resolver #"):
			scoped = false
		case strings.HasPrefix(f, "domain "):
			scoped = true
		case strings.HasPrefix(f, "nameserver[") && !scoped:
			_, v, ok := strings.Cut(f, ":")
			if !ok {
				continue
			}
			ip := strings.TrimSpace(v)
			if net.ParseIP(ip) == nil || own(ip) || seen[ip] {
				continue
			}
			seen[ip] = true
			servers = append(servers, net.JoinHostPort(ip, "53"))
		}
	}
	return servers
}

// resolvConfServers reads nameserver lines from a resolv.conf.
func resolvConfServers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var servers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil && !own(fields[1]) {
			servers = append(servers, net.JoinHostPort(fields[1], "53"))
		}
	}
	return servers
}

// forward sends the query to the first upstream that answers and returns
// its reply, or nil when none did in time.
func forward(q []byte) []byte {
	for _, addr := range upstream.find() {
		conn, err := net.DialTimeout("udp", addr, upstreamTimeout)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(upstreamTimeout))
		if _, err := conn.Write(q); err != nil {
			_ = conn.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err == nil && n >= 12 {
			return buf[:n]
		}
	}
	return nil
}
