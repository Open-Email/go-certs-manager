package dane

import "strings"

// RetiringRecord is the persisted marker for a DANE digest that is being retired
// after a key replacement. The previous key's digest MUST remain published in DNS
// until RetireAfter, because cluster nodes that haven't yet picked up the new
// certificate keep serving the old one — removing the old TLSA record early would
// hard-fail DANE validation against those nodes.
type RetiringRecord struct {
	Digest      string `json:"digest"`       // SPKI SHA-256 of the outgoing key
	RetireAfter int64  `json:"retire_after"` // unix seconds; safe to drop the record after this
}

// RetiringObjectName returns the storage key for a host's retiring-digest marker,
// relative to the storage base prefix. Lives under "dane/retiring/" so it is not
// confused with cert/key objects.
func RetiringObjectName(prefix, host string) string {
	return prefix + "dane/retiring/" + strings.ToLower(strings.TrimSuffix(host, "."))
}
