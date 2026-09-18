package certmanager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/storage"
)

// daneController computes the desired DANE TLSA records for the configured MX
// hosts from the stable certificate keys held in the KeyStore.
//
// Records are derived directly from key material — no separate rollover marker for
// the pre-publish phase:
//   - the live key (keys/<host>) always yields the current "3 1 1" digest
//   - a staged next key (keys/<host>.next) yields a second digest that must be
//     PRE-PUBLISHED before the new key is activated (RFC 7671 §8)
//
// After activation there is one extra concern: lagging cluster nodes keep serving
// the OLD certificate until they refresh, so the previous digest must remain
// published during a soak window. That window is recorded as a retiring marker
// (dane/retiring/<host>) written at activation and surfaced as an extra record
// tagged with its "keep until" time, so an operator never retires the old TLSA
// record early. The leader clears the marker once the soak elapses.
type daneController struct {
	keyStore *KeyStore
	backend  storage.Backend
	prefix   string
	mxHosts  []string
	mxSet    map[string]bool
	ttl      uint32
	soak     time.Duration

	// retiringMu serializes the read-modify-write of a host's retiring markers.
	retiringMu sync.Mutex
	logger     *slog.Logger
	// lookup resolves the TLSA records actually published in DNS; nil disables
	// published-record verification (drift alarm, issuance and activation gates).
	lookup dane.TLSALookup
}

func newDANEController(ks *KeyStore, backend storage.Backend, prefix string, mxHosts []string, ttl uint32, soak time.Duration, logger *slog.Logger) *daneController {
	if logger == nil {
		logger = slog.Default()
	}
	mxSet := make(map[string]bool, len(mxHosts))
	for _, h := range mxHosts {
		mxSet[strings.ToLower(strings.TrimSuffix(h, "."))] = true
	}
	return &daneController{
		keyStore: ks,
		backend:  backend,
		prefix:   prefix,
		mxHosts:  mxHosts,
		mxSet:    mxSet,
		ttl:      ttl,
		soak:     soak,
		logger:   logger,
	}
}

func (d *daneController) isMX(host string) bool {
	return d.mxSet[strings.ToLower(strings.TrimSuffix(host, "."))]
}

// DesiredRecords returns the TLSA records the operator should have published for
// every configured MX host: the current digest, the staged-next digest during a
// ceremony, and the retiring digest during a post-activation soak.
func (d *daneController) DesiredRecords(ctx context.Context) ([]dane.TLSARecord, error) {
	var records []dane.TLSARecord
	for _, host := range d.mxHosts {
		recs, err := d.recordsForHost(ctx, host)
		if err != nil {
			return nil, err
		}
		records = append(records, recs...)
	}
	return records, nil
}

func (d *daneController) recordsForHost(ctx context.Context, host string) ([]dane.TLSARecord, error) {
	var records []dane.TLSARecord

	liveKey, err := d.keyStore.LoadCertKey(ctx, host)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // no key yet (cert not issued)
		}
		return nil, fmt.Errorf("dane: load live key for %s: %w", host, err)
	}
	liveDigest, err := dane.SPKISHA256(liveKey.Public())
	if err != nil {
		return nil, err
	}
	records = append(records, dane.NewSPKIRecord(host, liveDigest, d.ttl))

	// Staged next key (rollover in progress) -> pre-publish its digest too.
	var nextDigest string
	if nextKey, err := d.keyStore.LoadNextCertKey(ctx, host); err == nil {
		nextDigest, err = dane.SPKISHA256(nextKey.Public())
		if err != nil {
			return nil, err
		}
		if nextDigest != liveDigest {
			r := dane.NewSPKIRecord(host, nextDigest, d.ttl)
			r.Note = "staged next key — pre-publish before activation"
			records = append(records, r)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("dane: load next key for %s: %w", host, err)
	}

	// Retiring digest (post-activation soak): keep publishing the previous key's
	// digest until RetireAfter so DANE validation on lagging nodes still serving the
	// old certificate does not fail. Pure read — the leader clears expired markers in
	// cleanupExpiredRetiring.
	// EVERY unexpired one: overlapping rotations leave more than one digest
	// still being served somewhere in the fleet.
	now := time.Now()
	retiring, err := d.retiring(ctx, host)
	if err != nil {
		// Answering without them would tell the operator to publish a set that
		// omits digests the fleet is still serving.
		return nil, err
	}
	for _, rec := range retiring {
		if rec.Expired(now) || rec.Digest == liveDigest || rec.Digest == nextDigest {
			continue
		}
		r := dane.NewSPKIRecord(host, rec.Digest, d.ttl)
		r.Note = "retiring — keep published until " + time.Unix(rec.RetireAfter, 0).UTC().Format(time.RFC3339)
		records = append(records, r)
	}

	return records, nil
}

// markRetiring records the CURRENT live key's digest as retiring, with a soak
// deadline. Must be called BEFORE the key is promoted (so "live" is still the old
// key). Leader-only by virtue of its caller (ActivateCertificateKey).
//
// Idempotent by digest: re-running an activation finds its own digest already
// retiring and leaves the deadline alone, so it cannot restart the soak the
// operator is counting down. A DIFFERENT digest is a different rotation and is
// added alongside, never over the top — dropping a digest the fleet is still
// serving is the failure this marker exists to prevent.
func (d *daneController) markRetiring(ctx context.Context, host string) error {
	if d.backend == nil {
		return nil
	}
	liveKey, err := d.keyStore.LoadCertKey(ctx, host)
	if err != nil {
		return fmt.Errorf("load live key for retiring marker: %w", err)
	}
	digest, err := dane.SPKISHA256(liveKey.Public())
	if err != nil {
		return err
	}

	// Both writers rebuild the list from what they read, so they must not
	// interleave: cleanup runs on the maintenance goroutine and this on an
	// operator's, and the loser of a race writes back a list missing whatever
	// the winner just added. Same process is the whole of it — both are
	// leader-only, and activation is serialized across nodes by the issuance
	// lease its caller holds.
	d.retiringMu.Lock()
	defer d.retiringMu.Unlock()

	existing, err := d.retiring(ctx, host)
	if err != nil {
		return err
	}

	now := time.Now()
	kept := make([]dane.RetiringRecord, 0, len(existing)+1)
	found := false
	for _, rec := range existing {
		if rec.Expired(now) {
			continue // pruned here rather than left to accumulate
		}
		if rec.Digest == digest {
			found = true
		}
		kept = append(kept, rec)
	}
	if found {
		return nil
	}
	rec := dane.RetiringRecord{Digest: digest, RetireAfter: now.Add(d.soak).Unix()}
	kept = append(kept, rec)

	if err := d.writeRetiring(ctx, host, kept); err != nil {
		return err
	}
	d.logger.Warn("TLS: DANE — recorded retiring digest; keep the OLD TLSA record published through the soak",
		"host", host, "digest", digest, "retire_after", time.Unix(rec.RetireAfter, 0).UTC().Format(time.RFC3339))
	return nil
}

// retiring reads a host's retiring markers, expired ones included.
//
// A missing object is (nil, nil); anything else is an error the caller must NOT
// treat as "there are none". Writers rebuild the whole list from what they read,
// so one transient GET failure would otherwise erase every digest recorded so
// far — which is the DANE hard failure this marker exists to prevent.
func (d *daneController) retiring(ctx context.Context, host string) ([]dane.RetiringRecord, error) {
	if d.backend == nil {
		return nil, nil
	}
	rc, err := d.backend.GetObject(ctx, dane.RetiringObjectName(d.prefix, host))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("dane: read retiring markers for %s: %w", host, err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("dane: read retiring markers for %s: %w", host, err)
	}
	records, err := dane.ParseRetiring(raw)
	if err != nil {
		// Unparseable is knowledge, not absence: the object is there and says
		// nothing usable, so a writer may replace it.
		d.logger.Warn("TLS: DANE — unreadable retiring marker; it will be replaced on the next rotation", "host", host, "error", err)
		return nil, nil
	}
	return records, nil
}

// writeRetiring persists a host's markers, removing the object when empty.
func (d *daneController) writeRetiring(ctx context.Context, host string, records []dane.RetiringRecord) error {
	key := dane.RetiringObjectName(d.prefix, host)
	if len(records) == 0 {
		return d.backend.RemoveObject(ctx, key)
	}
	data, err := dane.MarshalRetiring(records)
	if err != nil {
		return err
	}
	return d.backend.PutObject(ctx, key, strings.NewReader(string(data)), int64(len(data)),
		storage.PutOptions{ContentType: "application/json"})
}

// cleanupExpiredRetiring drops retiring digests whose soak has elapsed, and the
// marker itself once none are left. Leader-only.
func (d *daneController) cleanupExpiredRetiring(ctx context.Context) {
	if d.backend == nil {
		return
	}
	d.retiringMu.Lock()
	defer d.retiringMu.Unlock()

	now := time.Now()
	for _, host := range d.mxHosts {
		records, err := d.retiring(ctx, host)
		if err != nil {
			d.logger.Debug("TLS: skipping retiring cleanup — markers unreadable", "host", host, "error", err)
			continue
		}
		if len(records) == 0 {
			continue
		}
		kept := make([]dane.RetiringRecord, 0, len(records))
		var dropped []string
		for _, rec := range records {
			if rec.Expired(now) {
				dropped = append(dropped, rec.Digest)
				continue
			}
			kept = append(kept, rec)
		}
		if len(dropped) == 0 {
			continue
		}
		if err := d.writeRetiring(ctx, host, kept); err != nil {
			d.logger.Debug("TLS: failed to prune expired retiring digests", "host", host, "error", err)
			continue
		}
		d.logger.Info("TLS: DANE — soak elapsed; retiring digest dropped (safe to remove the old TLSA record)",
			"host", host, "digests", dropped, "still_retiring", len(kept))
	}
}

// verifyPublished compares the TLSA records actually published in DNS against
// the desired set for every MX host, logging drift loudly. Returns per-host
// match status for metrics; hosts whose lookup failed (indeterminate) or that
// have no key yet are omitted. Leader-only by virtue of its caller.
func (d *daneController) verifyPublished(ctx context.Context) map[string]bool {
	if d == nil || d.lookup == nil {
		return nil
	}
	status := make(map[string]bool, len(d.mxHosts))
	for _, host := range d.mxHosts {
		desired, err := d.recordsForHost(ctx, host)
		if err != nil || len(desired) == 0 {
			continue // no key yet (or transient storage error) — nothing to verify
		}
		published, err := d.lookup(ctx, host)
		if err != nil {
			d.logger.Debug("TLS: DANE — published TLSA verification skipped (lookup failed)", "host", host, "error", err)
			continue
		}
		if published.Empty() {
			d.logger.Warn("TLS: DANE drift — no TLSA records published in DNS", "host", host, "expected_records", len(desired))
			status[host] = false
			continue
		}
		ok := true
		desiredDigests := make(map[string]bool, len(desired))
		for _, rec := range desired {
			desiredDigests[rec.Cert] = true
			if !published.ContainsSPKIDigest(rec.Cert) {
				ok = false
				d.logger.Warn("TLS: DANE drift — desired TLSA record not published", "host", host, "record", rec.ZoneLine(), "note", rec.Note)
			}
		}
		for _, rr := range published.RRs {
			if rr.Usage == dane.UsageDANEEE && rr.Selector == dane.SelectorSPKI && rr.MatchingType == dane.MatchingSHA256 && !desiredDigests[rr.Cert] {
				ok = false
				d.logger.Warn("TLS: DANE drift — unknown TLSA record published (stale key or operator error)", "host", host, "rdata", "3 1 1 "+rr.Cert)
			}
		}
		if ok {
			d.logger.Debug("TLS: DANE — published TLSA records match the desired set",
				"host", host, "records", len(desired), "dnssec_validated", published.Authenticated)
		}
		status[host] = ok
	}
	return status
}

// gateIssuance blocks automatic issuance for an MX host when it would silently
// break DANE: no persistent key exists (issuing would mint a fresh one) while
// usage-3 TLSA records are still published in DNS. That state means the key was
// lost — the fix is restoring it (or removing the records), not re-creating it.
//
// With an existing key the gate never blocks — renewal reuses the key, so the
// SPKI cannot change; a digest mismatch is only warned (the drift alarm covers
// alerting) since blocking would stack cert expiry on top of the existing
// breakage. Indeterminate lookups fail open: certificate availability must not
// depend on DNS health. The manual RenewCertificate path bypasses this gate.
func (d *daneController) gateIssuance(ctx context.Context, host string) error {
	if d == nil || d.lookup == nil || !d.isMX(host) {
		return nil
	}
	liveKey, kerr := d.keyStore.LoadCertKey(ctx, host)
	switch {
	case kerr == nil:
		published, err := d.lookup(ctx, host)
		if err != nil || !published.HasDANEEE() {
			return nil
		}
		digest, err := dane.SPKISHA256(liveKey.Public())
		if err != nil {
			return nil
		}
		if !published.ContainsSPKIDigest(digest) {
			d.logger.Warn("TLS: DANE drift — published TLSA records do not include the live key's digest; issuing anyway (key reused, SPKI unchanged)",
				"host", host, "digest", digest)
		}
		return nil
	case errors.Is(kerr, os.ErrNotExist):
		published, err := d.lookup(ctx, host)
		if err != nil {
			d.logger.Warn("TLS: DANE — could not verify published TLSA before first issuance (proceeding)", "host", host, "error", err)
			return nil
		}
		if published.HasDANEEE() {
			return fmt.Errorf("dane: TLSA records are published for %s but no live key exists in storage — issuing would mint a new key and hard-fail DANE-validating senders; restore keys/%s (or remove the TLSA records), or use the manual renew-cert override", host, host)
		}
		return nil // bootstrap: nothing published yet
	default:
		return nil // storage trouble surfaces in the issuance path itself
	}
}
