package names

// Windows has no domain routes or trust yet, as it has no zone setup.

func platformTrust() error                          { return ErrNoTrust }
func domainRouted(domain string) (bool, string)     { return false, domain + ": not on Windows yet" }
func routeForeign(string) bool                      { return false }
func routesScript(_, _, _ []string) string          { return "" }
func uninstallRoutesScript([]string) string         { return "" }
func caTrusted(*CA) (bool, string)                  { return false, "not on Windows yet" }
func fingerprintTrusted(*CA, string) (bool, string) { return false, "" }
func trustedDozeRoots() []string                    { return nil }
func trustScript(*CA) string                        { return "" }
func untrustScript(*CA) string                      { return "" }
func untrustFingerprintScript(*CA, string) string   { return "" }
func untrustUnknownScript() []string                { return nil }
func platformRootsPEM() []byte                      { return nil }
