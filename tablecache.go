package names

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
)

// tableCache is the daemon's copy of the registered ports, and the rule for how
// stale it may be.
//
// A connection to a service that was registered a moment ago, or whose port
// was just replaced by a restart, must be translated by what the registry says
// now. A copy that is only re-read on a timer sends it to the port the last
// run had: refused when nothing listens there, or silently dropped. So the file
// is looked at again — one stat — whenever a connection is opened, and the
// whole table is rebuilt when it has been written to. The timer remains for
// what the file cannot say: a process that died without writing anything.
type tableCache struct {
	path string
	net  network

	mu    sync.Mutex
	stamp string
	table atomic.Pointer[portTable]
}

func newTableCache(path string, n network) *tableCache {
	c := &tableCache{path: path, net: n}
	c.refresh(true)
	return c
}

// current is the table to translate with.
func (c *tableCache) current() *portTable { return c.table.Load() }

// refresh rebuilds the table if the registry has been written since it was
// last read, or whatever it says if force is set.
func (c *tableCache) refresh(force bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The stamp is taken before the file is read: a write that lands in
	// between makes the next refresh see a different stamp and read again,
	// where taking it afterwards could record a stamp for a table that
	// predates it.
	stamp := ""
	if st, err := os.Stat(c.path); err == nil {
		stamp = strconv.FormatInt(st.ModTime().UnixNano(), 10) + "/" + strconv.FormatInt(st.Size(), 10)
	}
	if !force && stamp == c.stamp {
		return
	}
	c.table.Store(readPortTable(c.path, c.net))
	c.stamp = stamp
}
