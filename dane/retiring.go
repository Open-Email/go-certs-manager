package dane

import (
	"encoding/json"
	"strings"
	"time"
)

// RetiringRecord is the persisted marker for a DANE digest that is being retired
// after a key replacement. The previous key's digest MUST remain published in DNS
// until RetireAfter, because cluster nodes that haven't yet picked up the new
// certificate keep serving the old one — removing the old TLSA record early would
// hard-fail DANE validation against those nodes.
type RetiringRecord struct {
	Digest      string `json:"digest"`       // SPKI SHA-256 of the outgoing key
	RetireAfter int64  `json:"retire_after"` // unix seconds; safe to drop the record after this
}

// Expired reports whether this digest's soak has elapsed.
func (r RetiringRecord) Expired(now time.Time) bool { return now.Unix() >= r.RetireAfter }

// ParseRetiring reads a host's retiring markers.
//
// A LIST, because rotations overlap: A→B followed by B→C inside the first soak
// leaves both A and B being served somewhere in the fleet, and both digests have
// to stay published. A single slot could only hold one of them, and whichever it
// dropped would be an operator removing a TLSA record that nodes were still
// presenting — a DANE hard failure rather than a stale record.
//
// The single-object form is still read, because markers written before this
// change are in flight in exactly the situation that matters: mid-soak.
func ParseRetiring(raw []byte) ([]RetiringRecord, error) {
	var list []RetiringRecord
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var one RetiringRecord
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	if one.Digest == "" {
		return nil, nil
	}
	return []RetiringRecord{one}, nil
}

// RetiringObjectName returns the storage key for a host's retiring-digest marker,
// relative to the storage base prefix. Lives under "dane/retiring/" so it is not
// confused with cert/key objects.
func RetiringObjectName(prefix, host string) string {
	return prefix + "dane/retiring/" + strings.ToLower(strings.TrimSuffix(host, "."))
}
