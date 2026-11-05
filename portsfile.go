package names

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// PortsFile is beside the registry and holds the translated ports alone:
// host → the process that set them, and public → private. The registry's
// Entry.Ports says the same, but every doze program on the machine writes
// the registry, and one built before that field read the file into a type
// without it and wrote it back, so the mappings vanished. Nothing older
// knows this file, so nothing older can drop it. The network daemon reads
// both (readPortTable).
const PortsFile = "names.ports.json"

// portsEntry is one host's translated ports, and whose they are.
type portsEntry struct {
	PID int `json:"pid"`
	// IP is the address the ports were set at: a name claimed again at
	// another address does not carry them.
	IP    string         `json:"ip,omitempty"`
	Ports map[string]int `json:"ports"`
}

func portsPath(registry string) string {
	return filepath.Join(filepath.Dir(registry), PortsFile)
}

// readPorts is the ports file, or nothing.
func readPorts(registry string) map[string]portsEntry {
	m := map[string]portsEntry{}
	raw, err := os.ReadFile(portsPath(registry))
	if err != nil {
		return m
	}
	if json.Unmarshal(raw, &m) != nil {
		return map[string]portsEntry{}
	}
	return m
}

// writePorts sets host's ports for pid in the ports file, dropping hosts
// whose process is gone, under its own lock and with an atomic rename.
func writePorts(registry, host, ip string, pid int, ports map[string]int) error {
	path := portsPath(registry)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	unlock, err := lockFile(lock)
	if err != nil {
		return err
	}
	defer unlock()
	m := readPorts(registry)
	for h, e := range m {
		if !alive(e.PID) {
			delete(m, h)
		}
	}
	if len(ports) == 0 {
		if m[host].PID == pid {
			delete(m, host)
		}
	} else {
		m[host] = portsEntry{PID: pid, IP: ip, Ports: ports}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
