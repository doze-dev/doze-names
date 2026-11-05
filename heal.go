package names

import (
	"os"
	"strconv"
	"time"
)

// healEvery is how often a process with translated ports checks they are
// still in the registry. A stat each time; the file is read only when it
// changed.
const healEvery = 250 * time.Millisecond

// remember keeps a forward this process set, or forgets it when private is
// 0, and starts the healer the first time there is something to keep.
func (r *Registry) remember(host string, public, private int) {
	r.fwdMu.Lock()
	defer r.fwdMu.Unlock()
	if r.forwards == nil {
		r.forwards = map[string]map[string]int{}
	}
	key := strconv.Itoa(public)
	if private == 0 {
		delete(r.forwards[host], key)
		if len(r.forwards[host]) == 0 {
			delete(r.forwards, host)
		}
		return
	}
	if r.forwards[host] == nil {
		r.forwards[host] = map[string]int{}
	}
	r.forwards[host][key] = private
	if !r.healing {
		r.healing = true
		go r.heal()
	}
}

// heal puts this process's forwards back into the registry whenever the
// file changes and one is missing from a name it still holds. It stops when
// there is nothing left to keep.
//
// It exists because the registry is shared by every doze program on the
// machine, and one built before Entry.Ports read the file into a struct
// without the field and wrote it back: the mappings vanished within a
// moment of being written, and the network daemon refused every connection
// to the name ("connection refused" from a stack that looked healthy).
func (r *Registry) heal() {
	var seen time.Time
	for range time.Tick(healEvery) {
		r.fwdMu.Lock()
		if len(r.forwards) == 0 {
			r.healing = false
			r.fwdMu.Unlock()
			return
		}
		want := make(map[string]map[string]int, len(r.forwards))
		for host, ports := range r.forwards {
			want[host] = make(map[string]int, len(ports))
			for k, v := range ports {
				want[host][k] = v
			}
		}
		r.fwdMu.Unlock()

		st, err := os.Stat(r.path)
		if err != nil || st.ModTime().Equal(seen) {
			continue
		}
		seen = st.ModTime()
		_ = r.update(func(m map[string]Entry) error {
			for host, ports := range want {
				e, ok := m[host]
				if !ok || e.PID != r.pid {
					continue // released, or someone else's now: not ours to fix
				}
				missing := false
				for k, v := range ports {
					if e.Ports[k] != v {
						missing = true
					}
				}
				if !missing {
					continue
				}
				merged := map[string]int{}
				for k, v := range e.Ports {
					merged[k] = v
				}
				for k, v := range ports {
					merged[k] = v
				}
				e.Ports = merged
				m[host] = e
			}
			return nil
		})
		// What heal wrote moves the stamp; that is not a change to look at.
		if st, err := os.Stat(r.path); err == nil {
			seen = st.ModTime()
		}
	}
}

// forget drops every forward this process kept for host, here and in the
// ports file: the name was released, or claimed again at another address.
func (r *Registry) forget(host string) {
	r.fwdMu.Lock()
	_, had := r.forwards[host]
	delete(r.forwards, host)
	r.fwdMu.Unlock()
	if had {
		_ = writePorts(r.path, host, "", r.pid, nil)
	}
}
