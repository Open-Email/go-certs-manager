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
// Both forms are read. Entries with no digest are dropped: an empty one would
// become a malformed "3 1 1 " record and a drift warning that never clears.
func ParseRetiring(raw []byte) ([]RetiringRecord, error) {
	var list []RetiringRecord
	if err := json.Unmarshal(raw, &list); err != nil {
		var one RetiringRecord
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, err
		}
		list = []RetiringRecord{one}
	}
	out := make([]RetiringRecord, 0, len(list))
	for _, rec := range list {
		if rec.Digest != "" {
			out = append(out, rec)
		}
	}
	return out, nil
}

// MarshalRetiring writes the marker in the oldest form that can carry it: a
// single digest stays a bare object, which readers from before the list existed
// still understand.
//
// The fleet is not upgraded all at once, and a node on an older pin that meets
// an array reads no markers at all — then its own next write replaces them.
// Degrading only where the old shape genuinely cannot express the state (more
// than one rotation in flight) keeps the ordinary case safe across a rollout.
func MarshalRetiring(records []RetiringRecord) ([]byte, error) {
	if len(records) == 1 {
		return json.Marshal(records[0])
	}
	return json.Marshal(records)
}

// RetiringObjectName returns the storage key for a host's retiring-digest marker,
// relative to the storage base prefix. Lives under "dane/retiring/" so it is not
// confused with cert/key objects.
func RetiringObjectName(prefix, host string) string {
	return prefix + "dane/retiring/" + strings.ToLower(strings.TrimSuffix(host, "."))
}
