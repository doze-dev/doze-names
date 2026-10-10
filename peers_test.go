package names

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The zone is shared by programs that are built and released separately. These
// tests run them as what they are — separate processes with one home between
// them — rather than as several handles inside one. Each peer is this test
// binary, re-run with peerEnv set.

const (
	peerEnv      = "DOZE_NAMES_TEST_PEER"       // the owner to act as
	peerNamesEnv = "DOZE_NAMES_TEST_PEER_NAMES" // "service.stack,service.stack"
)

func TestMain(m *testing.M) {
	if owner := os.Getenv(peerEnv); owner != "" {
		runPeer(owner)
		return
	}
	os.Exit(m.Run())
}

// runPeer is one doze program: it claims its names, routes each to a little
// HTTP server that says who it is, joins the resolver and the front door, and
// runs until its stdin closes.
func runPeer(owner string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, owner) }))

	reg := Open(Home(), owner)
	for _, n := range strings.Split(os.Getenv(peerNamesEnv), ",") {
		service, stack, _ := strings.Cut(n, ".")
		lease, err := reg.Claim(Qualified(service, stack))
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		if err := lease.Route(ln.Addr().String()); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
	}
	ctx := context.Background()
	Serve(ctx, reg, nil)
	ServeIngress(ctx, reg, nil)
	fmt.Println("ready")
	io.Copy(io.Discard, os.Stdin) // until the test hangs up
}

type peer struct {
	owner string
	names []string // hosts
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func (p *peer) pid() int { return p.cmd.Process.Pid }

// zoneEnv is a private zone: a home and two addresses of its own.
type zoneEnv struct {
	home, dns, front string
}

func (z zoneEnv) env() []string {
	return append(os.Environ(), EnvHome+"="+z.home, EnvResolver+"="+z.dns, EnvIngress+"="+z.front)
}

func startPeer(t *testing.T, z zoneEnv, owner string, claims ...string) *peer {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(z.env(), peerEnv+"="+owner, peerNamesEnv+"="+strings.Join(claims, ","))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &peer{owner: owner, cmd: cmd, stdin: stdin}
	for _, c := range claims {
		service, stack, _ := strings.Cut(c, ".")
		p.names = append(p.names, Qualified(service, stack).Host)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	line, _ := bufio.NewReader(stdout).ReadString('\n')
	if strings.TrimSpace(line) != "ready" {
		t.Fatalf("peer %s did not come up: %q", owner, line)
	}
	return p
}

// eventually polls until check passes or the wait is over.
func eventually(t *testing.T, wait time.Duration, what string, check func() error) {
	t.Helper()
	deadline := time.Now().Add(wait)
	var err error
	for {
		if err = check(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %v", what, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// throughFrontDoor asks the zone's front door for host and returns the body.
func throughFrontDoor(front, host string) (string, error) {
	req, _ := http.NewRequest("GET", "http://"+front+"/", nil)
	req.Host = host
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return string(body), nil
}

// allAnswer checks every name of every live peer: it resolves through the
// zone's DNS server to the address the registry has, and the front door sends
// it to the peer that claimed it.
func allAnswer(t *testing.T, z zoneEnv, peers []*peer) error {
	snap := Open(z.home, "test").Snapshot()
	for _, p := range peers {
		for _, host := range p.names {
			e, ok := snap[host]
			if !ok {
				return fmt.Errorf("%s (%s) is not in the registry", host, p.owner)
			}
			if got := tryQueryA(z.dns, host); got != e.IP {
				return fmt.Errorf("%s resolved to %q, want %s", host, got, e.IP)
			}
			if body, err := throughFrontDoor(z.front, host); err != nil || body != p.owner {
				return fmt.Errorf("front door for %s answered %q, %v; want %s", host, body, err, p.owner)
			}
		}
	}
	return nil
}

// tryQueryA is queryA without a test to fail: "" when there is no answer.
func tryQueryA(server, host string) string {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return ""
	}
	defer conn.Close()
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(host, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(q); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < len(q)+16 || buf[7] == 0 {
		return ""
	}
	a := buf[n-4 : n]
	return net.IPv4(a[0], a[1], a[2], a[3]).String()
}

// The three tools, started in every order. Whichever came up first serves the
// zone for all three; every name resolves and is fronted regardless. Then the
// one that is serving is killed outright, as a crash would, and one of the
// others has to take over — for the names that are left, and not for the dead
// one's.
func TestThreeToolsShareOneZoneInAnyOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("starts nine processes and waits for takeovers")
	}
	tools := []struct {
		owner  string
		claims []string
	}{
		{"doze", []string{"db.shop", "api.shop"}},
		{"doze-aws", []string{"aws.shop"}},
		{"doze-kafka", []string{"kafka.shop", "schema.shop"}},
	}
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for _, order := range orders {
		var label []string
		for _, i := range order {
			label = append(label, tools[i].owner)
		}
		t.Run(strings.Join(label, ","), func(t *testing.T) {
			z := zoneEnv{home: t.TempDir(), dns: freeAddr(t, "udp"), front: freeAddr(t, "tcp")}
			var peers []*peer
			for _, i := range order {
				peers = append(peers, startPeer(t, z, tools[i].owner, tools[i].claims...))
			}
			reg := Open(z.home, "test")
			eventually(t, 5*time.Second, "all three up", func() error { return allAnswer(t, z, peers) })

			first := peers[0]
			if h, ok := reg.ResolverHolder(); !ok || h.PID != first.pid() {
				t.Fatalf("the first to start (%s, pid %d) should be serving DNS, the registry says %+v", first.owner, first.pid(), h)
			}
			if h, ok := reg.IngressHolder(); !ok || h.PID != first.pid() {
				t.Fatalf("the first to start (%s) should hold the front door, the registry says %+v", first.owner, h)
			}

			// It crashes. No shutdown hook runs.
			_ = first.cmd.Process.Signal(syscall.SIGKILL)
			_, _ = first.cmd.Process.Wait()
			rest := peers[1:]
			eventually(t, 3*retryInterval+2*time.Second, "a survivor took the zone over", func() error {
				h, ok := reg.ResolverHolder()
				if !ok || h.PID == first.pid() {
					return fmt.Errorf("nobody has taken DNS over yet (holder %+v)", h)
				}
				return allAnswer(t, z, rest)
			})
			for _, host := range first.names {
				if got := tryQueryA(z.dns, host); got != "" {
					t.Errorf("%s belonged to the dead %s and still resolves to %s", host, first.owner, got)
				}
				if body, err := throughFrontDoor(z.front, host); err == nil {
					t.Errorf("the front door still answers for the dead %s's %s: %q", first.owner, host, body)
				}
			}
		})
	}
}

// Two of them want the same name: a stack called shop with an aws module, and
// a standalone doze-aws instance called shop. First come keeps it, and the
// other is told who has it.
func TestASharedNameGoesToWhoeverCameFirst(t *testing.T) {
	z := zoneEnv{home: t.TempDir(), dns: freeAddr(t, "udp"), front: freeAddr(t, "tcp")}
	holder := startPeer(t, z, "doze-aws", "aws.shop")

	for k, v := range map[string]string{EnvHome: z.home, EnvResolver: z.dns, EnvIngress: z.front} {
		t.Setenv(k, v)
	}
	_, err := Open(z.home, "doze").Claim(Qualified("aws", "shop"))
	held, ok := Held(err)
	if !ok || held.Owner != "doze-aws" || held.PID != holder.pid() {
		t.Fatalf("the second claim = %v, want ErrHeld naming doze-aws (pid %d)", err, holder.pid())
	}
}
