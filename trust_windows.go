package names

// Windows has no domain routes or trust yet, as it has no zone setup.

func domainRouted(domain string) (bool, string) { return false, domain + ": not on Windows yet" }
func routeScript(string) string                 { return "" }
func unrouteScript(string) string               { return "" }
func caTrusted(*CA) (bool, string)              { return false, "not on Windows yet" }
func trustScript(*CA) string                    { return "" }
func untrustScript(*CA) string                  { return "" }
