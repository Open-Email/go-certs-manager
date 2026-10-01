package certmanager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

// issueLeaseTTL bounds how long a held issuance lease blocks other nodes. It must
// comfortably exceed a single issuance (issueTimeout) so the holder finishes before
// the lease can be taken over, while being short enough that a crashed holder's
// lease is reclaimed promptly.
const issueLeaseTTL = 5 * time.Minute

// issueLeaser provides best-effort, cluster-wide mutual exclusion for DRIVING an
// ACME order for a single domain, backed by the storage backend's atomic
// create-once (IfNoneMatch:"*"). It prevents two believed-leaders (split-brain,
// where the unfenced lexicographic IsLeader returns true on both sides of a
// partition) from issuing duplicate certificates and burning Let's Encrypt rate
// limits.
//
// It is the issuance counterpart to the storage-shared challenge tokens: the lease
// decides "who calls the CA", the challenge tokens decide "which node answers the
// CA's validation". Both nodes can reach S3 even across a node-to-node partition,
// so S3 is the arbiter that gossip cannot be.
//
// Taking over an EXPIRED lease (crashed holder) is one conditional write
// against the ETag the stale record was read with (IfMatch), so two nodes that
// both read it expired cannot both win: the first write changes the ETag and
// the second fails its precondition. It used to be read, delete, create — three
// steps two nodes interleaved, and the second delete removed the first node's
// fresh lease, so both drove orders for the same domain.
//
// What remains best-effort: expiry is the writer's wall clock, so clock skew
// shortens or lengthens a lease; and release is read-then-delete, so a holder
// releasing at the very moment its expired lease is taken over can delete the
// successor's. The TTL is sized so a live holder never reaches that moment
// (issueLeaseTTL against issueTimeout).
type issueLeaser struct {
	backend storage.Backend
	prefix  string
	nodeID  string
	ttl     time.Duration
	logger  *slog.Logger
}

type leaseRecord struct {
	Owner     string `json:"owner"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

func (l *issueLeaser) key(domain string) string {
	return l.prefix + "locks/issue/" + strings.ToLower(domain)
}

// acquire attempts to take the issuance lease for domain. Returns a release func
// and true on success, or (nil, false) if a live node already holds it. On any
// unexpected storage error it fails safe (returns false) so we never drive a
// duplicate order while uncertain.
func (l *issueLeaser) acquire(ctx context.Context, domain string) (func(), bool) {
	if l.backend == nil {
		return func() {}, true // single-node / tests: no coordination needed
	}
	key := l.key(domain)
	rec := leaseRecord{Owner: l.nodeID, ExpiresAt: time.Now().Add(l.ttl).Unix()}
	data, _ := json.Marshal(rec)

	if l.tryCreate(ctx, key, data) {
		return l.releaser(key), true
	}

	// Conflict: inspect the existing lease. If it has expired (crashed holder),
	// attempt a single take-over, conditional on the record being the one we
	// read. Otherwise back off. The ETag is taken BEFORE the record is read:
	// a record that changed in between is a fresh lease, and reads as one.
	info, err := l.backend.StatObject(ctx, key)
	if err != nil {
		return nil, false // released meanwhile, or unreadable: next tick
	}
	existing, err := l.read(ctx, key)
	if err != nil || time.Now().Unix() < existing.ExpiresAt {
		return nil, false
	}
	l.logger.Warn("TLS: taking over expired issuance lease", "domain", domain, "stale_owner", existing.Owner)
	if l.takeOver(ctx, key, data, info.ETag) {
		return l.releaser(key), true
	}
	return nil, false
}

// takeOver replaces an expired lease record, succeeding only if it is still
// the record read with etag. A failed precondition means a peer took it over
// first.
func (l *issueLeaser) takeOver(ctx context.Context, key string, data []byte, etag string) bool {
	err := l.backend.PutObject(ctx, key, strings.NewReader(string(data)), int64(len(data)),
		storage.PutOptions{ContentType: "application/json", IfMatch: etag})
	if err == nil {
		return true
	}
	var condErr *storage.ConditionalPutError
	if errors.As(err, &condErr) {
		return false // a peer took it over first
	}
	l.logger.Warn("TLS: issuance lease take-over failed; deferring issuance", "key", key, "error", err)
	return false
}

func (l *issueLeaser) tryCreate(ctx context.Context, key string, data []byte) bool {
	err := l.backend.PutObject(ctx, key, strings.NewReader(string(data)), int64(len(data)),
		storage.PutOptions{ContentType: "application/json", IfNoneMatch: "*"})
	if err == nil {
		return true
	}
	var condErr *storage.ConditionalPutError
	if errors.As(err, &condErr) {
		return false // someone else holds it
	}
	// Unexpected storage error: fail safe — skip issuance this round rather than
	// risk a duplicate order. (Issuance needs storage to persist the cert anyway.)
	l.logger.Warn("TLS: issuance lease put failed; deferring issuance", "key", key, "error", err)
	return false
}

func (l *issueLeaser) read(ctx context.Context, key string) (leaseRecord, error) {
	rc, err := l.backend.GetObject(ctx, key)
	if err != nil {
		return leaseRecord{}, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return leaseRecord{}, err
	}
	var rec leaseRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return leaseRecord{}, err
	}
	return rec, nil
}

// releaser returns a release func that deletes the lease only if we still own it,
// so we never delete a lease a peer legitimately took over after ours expired.
func (l *issueLeaser) releaser(key string) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if rec, err := l.read(ctx, key); err == nil && rec.Owner != l.nodeID {
			return // a peer owns it now; leave it alone
		}
		if err := l.backend.RemoveObject(ctx, key); err != nil {
			l.logger.Debug("TLS: failed to release issuance lease", "key", key, "error", err)
		}
	}
}

// randNodeID returns a stable-for-this-process identifier used as the lease owner.
// Uniqueness (not human-readability) is all the lease semantics require.
func randNodeID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("pid-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
