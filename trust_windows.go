package names

// Windows has no domain routes or trust yet, as it has no zone setup.

func platformTrust() error                      { return ErrNoTrust }
func domainRouted(domain string) (bool, string) { return false, domain + ": not on Windows yet" }
func routesScript([]string, []string) string    { return "" }
func caTrusted(*CA) (bool, string)              { return false, "not on Windows yet" }
func fingerprintTrusted(string) (bool, string)  { return false, "" }
func trustScript(*CA) string                    { return "" }
func untrustScript(*CA) string                  { return "" }
func untrustFingerprintScript(string) string    { return "" }
