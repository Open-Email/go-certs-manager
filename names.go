package certmanager

import (
	"strings"

	"golang.org/x/net/idna"
)

// normalizeDomain returns the one spelling a name is filed under everywhere:
// lower case, no trailing dot, and punycode. Clients send the A-label in SNI
// (RFC 6066), so a Unicode name in configuration — "bücher.example" — matched
// nothing at the handshake and was ordered as typed, which the CA refuses. A
// name that is not valid IDNA is kept as typed, lower-cased.
func normalizeDomain(name string) string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if ascii, err := idna.Lookup.ToASCII(name); err == nil && ascii != "" {
		return ascii
	}
	return name
}

// domainSetOf is the configured domains, each under its one spelling.
func domainSetOf(domains []string) map[string]bool {
	set := make(map[string]bool, len(domains))
	for _, d := range domains {
		if n := normalizeDomain(d); n != "" {
			set[n] = true
		}
	}
	return set
}

// normalizeDomains returns the names under their one spelling, in order,
// empty entries dropped.
func normalizeDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if n := normalizeDomain(d); n != "" {
			out = append(out, n)
		}
	}
	return out
}
