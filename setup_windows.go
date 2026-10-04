package names

import "errors"

// Windows has no machine setup yet: the loopback pool, the resolver route and the
// hosts block each have a different mechanism there, and none is written. Check says
// so as a step that is not done, so `dns-setup --check` and `doctor` explain
// themselves, and Install and Uninstall fail with the same sentence instead of
// reporting a success that changed nothing.
//
// The registry, the resolver and the front door still build and run where the OS
// allows the binds; names simply do not resolve without a setup, so callers fall back
// to an address.

var errWindows = errors.New(".doze names are not supported on Windows yet: nothing was changed")

func check() Status {
	return Status{Platform: "windows", Steps: []Step{{
		Name: "resolver", Done: false, Detail: "not supported on Windows yet",
	}}}
}

func install(Options) error   { return errWindows }
func uninstall(Options) error { return errWindows }
