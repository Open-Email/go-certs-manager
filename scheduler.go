package certmanager

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/internal/safego"
)

// startMaintenance launches the background loop that keeps certificates current:
//   - on the leader: issue missing certs and renew certs within the renewal window
//     (always reusing the persistent key, so the SPKI never changes)
//   - on followers: refresh certs from storage so they serve what the leader issued
func (m *Manager) startMaintenance() {
	safego.Go(m.logger, "tls-maintenance", func() {
		defer close(m.doneCh)

		m.maintainOnce() // run immediately so a fresh node obtains/serves promptly

		ticker := time.NewTicker(m.checkInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.maintainOnce()
			case <-m.stopCh:
				m.logger.Info("TLS maintenance loop stopped")
				return
			}
		}
	})
}

func (m *Manager) maintainOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), issueTimeout+30*time.Second)
	defer cancel()

	leader := m.isLeader()
	for _, domain := range m.domains {
		if leader {
			m.reconcileCeremony(ctx, domain)
			if err := m.renewIfNeeded(ctx, domain); err != nil {
				m.logger.Warn("TLS: maintenance issue/renew failed", "domain", domain, "error", err)
			}
		} else {
			if _, err := m.certCache.Refresh(ctx, domain); err != nil {
				m.logger.Debug("TLS: follower refresh found no certificate yet", "domain", domain, "error", err)
			}
		}
	}

	// Drift alarm: leader-only so a mismatch alerts once, not once per node.
	if m.dane != nil && leader {
		m.dane.cleanupExpiredRetiring(ctx)
		for host, ok := range m.dane.verifyPublished(ctx) {
			if m.onDANEMatch != nil {
				m.onDANEMatch(host, ok)
			}
		}
	}

	m.maintainOnDemand(leader)
}

// maintainOnDemand is the same duty for the DYNAMIC allow-set, and it is a
// separate function because the static list's shape does not survive contact
// with thousands of hostnames:
//
//   - EVERY host gets its OWN context. The static loop runs under one
//     issueTimeout-sized deadline, which is right for a handful of names and
//     wrong for many: past the deadline every remaining host fails with
//     "context deadline exceeded", and each of those failures would be recorded
//     against its retry budget for a problem that was ours, not theirs.
//   - Issuance is BOUNDED and CONCURRENT (MaxConcurrentOrders): serialized
//     orders would let one slow CA response set the pace for the whole set.
//   - RENEWALS GO FIRST. When the new-order budget is the scarce resource, a
//     working service staying up beats a new one starting.
//   - The DNS pre-flight runs before EVERY order, renewals included; only the
//     new-order token bucket is first-issuance-only. See the loop body.
//   - Followers refresh only what the leader's index says CHANGED, instead of
//     one storage read per hostname per tick.
func (m *Manager) maintainOnDemand(leader bool) {
	if m.onDemand == nil {
		return
	}
	hosts := m.onDemand.hosts()
	if len(hosts) == 0 {
		return
	}

	if !leader {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		for _, host := range m.onDemand.changedSince(ctx, hosts) {
			if _, err := m.certCache.Refresh(ctx, host); err != nil {
				m.logger.Debug("TLS: on-demand follower refresh found nothing yet", "domain", host, "error", err)
				continue
			}
			// Adopt only on success, so a failed read is retried next tick rather
			// than remembered as done (the handshake path cannot heal it: it
			// serves whatever is already in memory).
			m.onDemand.noteRefreshed(ctx, host)
		}
		return
	}

	// LOAD BEFORE JUDGING. On-demand hostnames are not in preload() — that only
	// covers the static list — so after a restart the leader holds nothing in
	// memory for names whose certificates are sitting in storage. Classifying
	// from memory alone would call every one of them a first issuance, spend the
	// hour's new-order budget re-obtaining certificates we already have, and
	// starve the renewals that actually needed it. The shared index answers most
	// of it for free; only hostnames it does not cover cost a storage read, and
	// only until they are in memory.
	loadCtx, loadCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	for _, host := range hosts {
		if _, have := m.certCache.leafNotAfter(host); have {
			continue
		}
		if _, known := m.onDemand.indexNotAfter(host); !known {
			continue
		}
		if _, err := m.certCache.Refresh(loadCtx, host); err != nil {
			m.logger.Debug("TLS: on-demand certificate in index but not loadable", "domain", host, "error", err)
		}
	}
	loadCancel()

	// Split the work before doing any of it, so ordering is a property of the
	// plan rather than of which host happened to come first.
	var renewals, fresh []string
	for _, host := range hosts {
		notAfter, have := m.certCache.leafNotAfter(host)
		switch {
		case !have:
			fresh = append(fresh, host)
		case time.Until(notAfter) <= m.renewBefore:
			renewals = append(renewals, host)
		}
	}
	if len(renewals) == 0 && len(fresh) == 0 {
		return
	}

	sem := make(chan struct{}, m.onDemand.cfg.MaxConcurrentOrders)
	var wg sync.WaitGroup
	// safego, not a bare `go`: a panic in one hostname's issuance must not take
	// down a process serving every other hostname's traffic.
	run := func(host string, isRenewal bool) {
		defer wg.Done()
		defer func() { <-sem }()
		// Per-host deadline: one hostname's slow CA cannot consume the budget of
		// the hostnames queued behind it.
		ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
		defer cancel()

		// The pre-flight guards RENEWALS TOO. A renewal for a name that no
		// longer points here cannot succeed, so the lookup is pure savings; and
		// unlike a first issuance it is the case nothing else bounds. A hostname
		// leaves the allow-set only when the authority notices its DNS changed,
		// which happens on someone's explicit check and not otherwise — so a
		// customer who verified a hostname, got a certificate, and then quietly
		// deleted the record stays enumerated indefinitely. Renewing it blind
		// made every such hostname a permanent failed-order loop bounded only
		// by the per-host retry budget, all of it charged to the account limit
		// the platform's own static names renew under. A failed pre-flight
		// costs the renewal a 24-hour backoff, which a 30-day window absorbs
		// without anyone noticing.
		if ok, reason := m.onDemand.preflightOK(ctx, host); !ok {
			m.logger.Debug("TLS: on-demand issue/renew skipped — DNS pre-flight", "domain", host, "renewal", isRenewal, "reason", reason)
			return
		}
		// The new-order budget stays first-issuance only: renewals are bounded
		// by certificate lifetime and must never be starved by an import.
		if !isRenewal && !m.onDemand.orders.take() {
			m.logger.Info("TLS: on-demand new-order budget exhausted for this hour — deferring", "domain", host)
			return
		}
		if err := m.renewIfNeeded(ctx, host); err != nil {
			m.logger.Warn("TLS: on-demand issue/renew failed", "domain", host, "renewal", isRenewal, "error", err)
			return
		}
		if notAfter, ok := m.certCache.leafNotAfter(host); ok {
			m.onDemand.noteIssued(ctx, host, notAfter)
		}
	}
	for _, group := range []struct {
		hosts     []string
		isRenewal bool
	}{{renewals, true}, {fresh, false}} {
		for _, host := range group.hosts {
			sem <- struct{}{}
			wg.Add(1)
			host, isRenewal := host, group.isRenewal
			safego.Go(m.logger, "tls-ondemand-issue", func() { run(host, isRenewal) })
		}
	}
	wg.Wait()
}

// reconcileCeremony completes a key-replacement ceremony that was interrupted
// after the new certificate was issued and stored but before the staged key was
// promoted (e.g. the leader crashed or lost leadership between Store and Promote).
// In that state storage holds: leaf SPKI == next-key SPKI != live-key SPKI, and a
// follower/new-leader would otherwise be stuck (the chain can't be served against
// the old live key — ErrKeyCertMismatch). Rolling forward is safe and idempotent
// because the new cert is already issued and durable. Leader-only.
func (m *Manager) reconcileCeremony(ctx context.Context, domain string) {
	nextKey, err := m.keyStore.LoadNextCertKey(ctx, domain)
	if err != nil {
		return // no ceremony staged (or transient storage error)
	}
	nextSPKI, err := dane.SPKISHA256(nextKey.Public())
	if err != nil {
		return
	}
	leafSPKI, err := m.certCache.storedLeafSPKI(ctx, domain)
	if err != nil {
		return // no stored chain yet — ceremony not past Issue/Store
	}
	liveKey, err := m.keyStore.LoadCertKey(ctx, domain)
	if err != nil {
		return
	}
	liveSPKI, err := dane.SPKISHA256(liveKey.Public())
	if err != nil {
		return
	}

	// Stored cert is bound to the staged next key, but the live key wasn't promoted.
	if leafSPKI == nextSPKI && liveSPKI != nextSPKI {
		m.logger.Warn("TLS: completing interrupted key-replacement (promoting staged key)", "domain", domain)
		if err := m.keyStore.PromoteNextCertKey(ctx, domain); err != nil {
			m.logger.Error("TLS: failed to complete interrupted key-replacement", "domain", domain, "error", err)
			return
		}
		if _, err := m.certCache.Refresh(ctx, domain); err != nil {
			m.logger.Warn("TLS: refresh after completing key-replacement failed", "domain", domain, "error", err)
		}
	}
}

// renewIfNeeded issues a missing certificate or renews one inside the renewal
// window. Leader-only (callers ensure this).
func (m *Manager) renewIfNeeded(ctx context.Context, domain string) error {
	notAfter, have := m.certCache.leafNotAfter(domain)
	if !have {
		// No in-memory cert; try storage, else issue.
		if _, err := m.certCache.Refresh(ctx, domain); err == nil {
			notAfter, have = m.certCache.leafNotAfter(domain)
		}
	}
	if have && time.Until(notAfter) > m.renewBefore {
		return nil // still fresh
	}

	unlock := m.inflight.lock(strings.ToLower(domain))
	defer unlock()

	// Re-check after winning the lock: a concurrent RenewCertificate/obtain may have
	// already issued a fresh cert while we were blocked, making this issuance redundant.
	if na, ok := m.certCache.leafNotAfter(domain); ok && time.Until(na) > m.renewBefore {
		return nil
	}

	if err := m.dane.gateIssuance(ctx, domain); err != nil {
		return err
	}
	certKey, err := m.keyStore.LoadOrCreateCertKey(ctx, domain)
	if err != nil {
		return err
	}
	if _, err := m.issueWithKey(ctx, domain, certKey); err != nil {
		return err
	}
	if have {
		m.logger.Info("TLS: certificate renewed (key reused — SPKI unchanged)", "domain", domain, "old_not_after", notAfter)
	} else {
		m.logger.Info("TLS: certificate issued", "domain", domain)
	}
	return nil
}

// ReplaceCertificateKey begins a deliberate key-replacement ceremony for a domain
// (e.g. after key compromise). It stages a NEW key but does NOT serve it yet, and
// returns the TLSA records that must be published (current + next) so the next
// key's digest is in DNS BEFORE it is activated. Leader-only.
//
// Ceremony: ReplaceCertificateKey -> publish returned records -> wait for TTL/
// propagation -> ActivateCertificateKey -> (after soak) remove the old record.
func (m *Manager) ReplaceCertificateKey(domain string) ([]dane.TLSARecord, error) {
	if m == nil {
		return nil, fmt.Errorf("TLS manager not initialized")
	}
	if !m.isLeader() {
		return nil, fmt.Errorf("key replacement must be performed on the cluster leader node")
	}
	domain = strings.ToLower(domain)
	if !m.domainSet[domain] {
		return nil, fmt.Errorf("domain %q is not in the configured domain list", domain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := m.keyStore.GenerateNextCertKey(ctx, domain); err != nil {
		return nil, fmt.Errorf("stage next key for %s: %w", domain, err)
	}
	m.logger.Warn("TLS: staged replacement key — PUBLISH the next TLSA record and wait for propagation before activating", "domain", domain)

	if m.dane != nil {
		return m.dane.recordsForHost(ctx, domain)
	}
	// DANE disabled: still surface the staged digest for any manual pinning.
	next, err := m.keyStore.LoadNextCertKey(ctx, domain)
	if err != nil {
		return nil, err
	}
	digest, err := dane.SPKISHA256(next.Public())
	if err != nil {
		return nil, err
	}
	return []dane.TLSARecord{dane.NewSPKIRecord(domain, digest, 3600)}, nil
}

// ActivateCertificateKey completes a key-replacement ceremony: it issues a
// certificate bound to the staged next key, serves it, and promotes the next key
// to the live slot. Only run AFTER the next key's TLSA record has been published
// and propagated — for DANE MX hosts this is enforced by a DNS lookup: the
// staged key's "3 1 1" record must be visible (force skips the check, e.g. for
// split-horizon DNS the server can't see). Leader-only.
func (m *Manager) ActivateCertificateKey(domain string, force bool) error {
	if m == nil {
		return fmt.Errorf("TLS manager not initialized")
	}
	if !m.isLeader() {
		return fmt.Errorf("key activation must be performed on the cluster leader node")
	}
	domain = strings.ToLower(domain)
	if !m.domainSet[domain] {
		return fmt.Errorf("domain %q is not in the configured domain list", domain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
	defer cancel()

	unlock := m.inflight.lock(domain)
	defer unlock()

	// Serialize the ceremony cluster-wide too: a second believed-leader must not
	// drive a parallel order/activation for the same domain.
	release, ok := m.acquireIssueLease(ctx, domain)
	if !ok {
		return fmt.Errorf("cannot activate %s: issuance lease held by another node — retry shortly", domain)
	}
	defer release()

	nextKey, err := m.keyStore.LoadNextCertKey(ctx, domain)
	if err != nil {
		return fmt.Errorf("no staged replacement key for %s (run ReplaceCertificateKey first): %w", domain, err)
	}

	// Activation gate: refuse to swap the served SPKI until DNS shows the staged
	// key's TLSA record. Fail-closed both ways (mismatch AND indeterminate
	// lookup) — the operator is present and can retry or force.
	if m.dane != nil && m.dane.isMX(domain) && m.dane.lookup != nil {
		digest, derr := dane.SPKISHA256(nextKey.Public())
		if derr != nil {
			return derr
		}
		published, lerr := m.dane.lookup(ctx, domain)
		switch {
		case force:
			if lerr != nil || !published.ContainsSPKIDigest(digest) {
				m.logger.Warn("TLS: DANE — activation FORCED without confirmed TLSA publication of the staged key", "domain", domain, "digest", digest)
			}
		case lerr != nil:
			return fmt.Errorf("cannot verify the staged key's TLSA record is published for %s (lookup failed: %v) — retry, or force activation", domain, lerr)
		case !published.ContainsSPKIDigest(digest):
			return fmt.Errorf("staged key's TLSA record (3 1 1 %s) is not visible in DNS for %s — publish it, wait for TTL propagation, then retry (or force activation)", digest, domain)
		default:
			if !published.Authenticated {
				m.logger.Info("TLS: DANE — staged TLSA record is visible but the DNS answer was not DNSSEC-validated (AD bit unset); DANE requires a signed zone", "domain", domain)
			}
		}
	}

	issuer, err := m.ensureIssuer(ctx)
	if err != nil {
		return err
	}
	chainPEM, err := issuer.Issue(ctx, domain, nextKey)
	if err != nil {
		return fmt.Errorf("issue cert with next key for %s: %w", domain, err)
	}
	// Serve the new cert (bound to the next key) before promoting, so storage and
	// the live key converge; PromoteNextCertKey then makes keyFor match the chain.
	if _, err := m.certCache.Store(ctx, domain, chainPEM, nextKey); err != nil {
		return fmt.Errorf("store cert for %s: %w", domain, err)
	}
	// Record the OUTGOING (still-live) digest for the DANE soak window BEFORE
	// promoting, so the operator keeps the old TLSA record published until lagging
	// nodes converge on the new cert.
	if m.dane != nil && m.dane.isMX(domain) {
		if err := m.dane.markRetiring(ctx, domain); err != nil {
			m.logger.Warn("TLS: failed to record retiring DANE digest", "domain", domain, "error", err)
		}
	}
	// Re-check leadership immediately before the destructive promote: if this node
	// flapped during issuance, abort rather than overwrite the live key. The stored
	// chain is already bound to the next key, so reconcileCeremony on the (re-elected)
	// leader will roll the promotion forward idempotently.
	if !m.isLeader() {
		return fmt.Errorf("lost leadership before promoting next key for %s; will be completed by the leader", domain)
	}
	if err := m.keyStore.PromoteNextCertKey(ctx, domain); err != nil {
		return fmt.Errorf("promote next key for %s: %w", domain, err)
	}
	m.logger.Warn("TLS: activated replacement key — serving new SPKI; retire the OLD TLSA record only after the soak period", "domain", domain)
	return nil
}
