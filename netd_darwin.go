package names

// The macOS network daemon: the one process that makes every address in the
// block reachable (see pool.go for why there is one, and nat.go for what it
// does to a packet).
//
// launchd starts it as root, because opening a tunnel interface and adding a
// route need root. It does those two things, gives up root for good, and from
// then on only reads the registry and copies packets as the user who ran
// setup. It is any doze program run with helperArg — setup installs a copy of
// whichever one the user had — so there is nothing separate to release or
// keep in step.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	utunControl  = "com.apple.net.utun_control"
	utunOptName  = 2 // UTUN_OPT_IFNAME
	sysprotoCtl  = 2 // SYSPROTO_CONTROL
	utunHeader   = 4 // the address family, ahead of every packet
	netdMTU      = 16384
	tableRefresh = time.Second
)

// runNetd is the daemon. args are the registry file, and the uid and gid to
// run as once the interface is up.
func runNetd(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: " + helperArg + " <registry> <uid> <gid>")
	}
	registry := args[0]
	uid, err1 := strconv.Atoi(args[1])
	gid, err2 := strconv.Atoi(args[2])
	if err1 != nil || err2 != nil || uid <= 0 {
		return errors.New("netd: the uid and gid to run as must be numbers, and not root's")
	}

	if owner := routeOwner(zone.at(dynamicBase).String()); owner != "" {
		return fmt.Errorf("netd: %s is already routed (%s): another program is using the block", zone.cidr(), owner)
	}
	fd, ifname, err := openTunnel()
	if err != nil {
		return fmt.Errorf("netd: open the interface: %w", err)
	}
	gw := zone.gateway().String()
	for _, c := range [][]string{
		{"/sbin/ifconfig", ifname, "inet", gw, gw, "netmask", "255.255.255.255", "mtu", strconv.Itoa(netdMTU), "up"},
		{"/sbin/route", "-n", "add", "-net", zone.cidr(), "-interface", ifname},
	} {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("netd: %s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}

	// Root's work is done. Everything from here reads a file the user owns
	// and handles packets from the user's own programs.
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("netd: drop groups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("netd: drop gid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("netd: drop uid: %w", err)
	}
	fmt.Fprintf(os.Stderr, "netd: %s on %s, translating from %s as uid %d\n", zone.cidr(), ifname, registry, uid)
	// Say which home this daemon serves, where the programs of that home look:
	// a pid in the home, so a daemon started by hand is found the same way a
	// launchd one is, and a zone moved with DOZE_HOME is known to have none.
	if err := writeServing(registry); err != nil {
		fmt.Fprintf(os.Stderr, "netd: cannot record that it serves %s: %v\n", registry, err)
	}

	cache := newTableCache(registry, zone)
	// A rewrite of the file is noticed when a connection opens (below); this is
	// for what the file cannot say, a service that died without writing.
	go func() {
		for range time.Tick(tableRefresh) {
			cache.refresh(true)
		}
	}()

	var gwAddr [4]byte
	copy(gwAddr[:], zone.gateway())
	buf := make([]byte, utunHeader+65535)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("netd: read: %w", err)
		}
		if n <= utunHeader || buf[3] != unix.AF_INET {
			continue
		}
		p := buf[utunHeader:n]
		if firstPacket(p) {
			cache.refresh(false)
		}
		if !translate(p, gwAddr, cache.current()) {
			continue
		}
		if _, err := unix.Write(fd, buf[:utunHeader+packetLen(p)]); err != nil && !errors.Is(err, unix.ENOBUFS) {
			return fmt.Errorf("netd: write: %w", err)
		}
	}
}

// firstPacket reports whether p opens a TCP connection.
func firstPacket(p []byte) bool {
	ihl := int(p[0]&0x0f) * 4
	return len(p) >= ihl+20 && p[9] == protoTCP && p[ihl+13]&(tcpSYN|tcpACK) == tcpSYN
}

// openTunnel creates a utun interface and returns its descriptor and name. The
// interface exists for as long as the descriptor is open.
func openTunnel() (int, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoCtl)
	if err != nil {
		return 0, "", err
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControl)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		_ = unix.Close(fd)
		return 0, "", err
	}
	// Unit 0 asks for the next free utun.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		_ = unix.Close(fd)
		return 0, "", err
	}
	name, err := unix.GetsockoptString(fd, sysprotoCtl, utunOptName)
	if err != nil {
		_ = unix.Close(fd)
		return 0, "", err
	}
	return fd, name, nil
}

// routeOwner returns what an address is routed to when that is something more
// specific than the default route, and "" when the block is free to take.
func routeOwner(ip string) string {
	out, err := exec.Command("/sbin/route", "-n", "get", ip).Output()
	if err != nil {
		return ""
	}
	var dest, iface string
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), ":")
		switch k {
		case "destination":
			dest = strings.TrimSpace(v)
		case "interface":
			iface = strings.TrimSpace(v)
		}
	}
	if dest == "" || dest == "default" {
		return ""
	}
	return dest + " on " + iface
}

// servingFile is the file, beside the registry, that names the daemon serving
// it.
const servingFile = "netd.pid"

func writeServing(registry string) error {
	dir := filepath.Dir(registry)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, servingFile), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
}
