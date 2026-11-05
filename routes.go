package names

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// Which project asked for each domain route. A route is machine-wide and
// privileged to install, so it must be known who still wants it: when a
// domain leaves a project's doze.hcl, or the project folder is gone, its
// route is stale and the next privileged run (doze trust, or dns-setup
// --uninstall) removes it, and doctor says so until then. Nothing in
// /etc/resolver that this file does not list is ever touched.

const routesFile = "routes.json"

// routes is domain → the project folders that declare it.
type routes map[string][]string

func routesPath(home string) string { return filepath.Join(home, routesFile) }

func readRoutes(home string) routes {
	out := routes{}
	if b, err := os.ReadFile(routesPath(home)); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func writeRoutes(home string, rs routes) error {
	if err := os.MkdirAll(home, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(routesPath(home), append(b, '\n'), 0o644)
}

// RecordDomains says what a project declares now, replacing what it said
// before: a domain it dropped loses this project as a reason to be routed.
func RecordDomains(home, dir string, domains []string) error {
	rs := readRoutes(home)
	want := map[string]bool{}
	for _, d := range RouteDomains(domains) {
		want[d] = true
	}
	for d, dirs := range rs {
		rs[d] = without(dirs, dir)
		if len(rs[d]) == 0 && !want[d] {
			if routed, _ := domainRouted(d); routed {
				// Kept with no claimant, so StaleRoutes reports it until the
				// route is removed from the machine.
				rs[d] = []string{}
			} else {
				delete(rs, d) // never routed, or already removed: nothing to remember
			}
		}
	}
	for d := range want {
		rs[d] = append(without(rs[d], dir), dir)
	}
	return writeRoutes(home, rs)
}

// ForgetProject drops a project from every route it declared: the folder
// is gone, or doze trust --remove ran for it.
func ForgetProject(home, dir string) error {
	rs := readRoutes(home)
	for d, dirs := range rs {
		rs[d] = without(dirs, dir)
	}
	return writeRoutes(home, rs)
}

// RecordedRoutes lists every domain this machine was asked to route, with
// or without a claimant left.
func RecordedRoutes(home string) []string {
	rs := readRoutes(home)
	out := make([]string, 0, len(rs))
	for d := range rs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// StaleRoutes lists the routed domains no project declares any more: every
// claimant dropped it, or every claimant's folder is gone. Folders are
// checked here, so a deleted project needs no step of its own.
func StaleRoutes(home string) []string {
	rs := readRoutes(home)
	var out []string
	for d, dirs := range rs {
		if !declared(dirs) {
			if routed, _ := domainRouted(d); routed {
				out = append(out, d)
			}
		}
	}
	sort.Strings(out)
	return out
}

// RouteRemoved forgets a stale domain once its route is gone.
func RouteRemoved(home, domain string) error {
	rs := readRoutes(home)
	if dirs, ok := rs[domain]; ok && !declared(dirs) {
		delete(rs, domain)
		return writeRoutes(home, rs)
	}
	return nil
}

// declared says one of the folders still has a doze.hcl: a claimant that
// may still mean it.
func declared(dirs []string) bool {
	for _, dir := range dirs {
		if st, err := os.Stat(filepath.Join(dir, "doze.hcl")); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func without(dirs []string, dir string) []string {
	out := dirs[:0:0]
	for _, d := range dirs {
		if d != dir {
			out = append(out, d)
		}
	}
	return out
}
