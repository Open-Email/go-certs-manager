package certmanager

import (
	"context"
	"errors"
	"fmt"
	"os"
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
//
// tickContext is a deadline that also dies with the manager. Stop() waits ten
// seconds; without this, work started on a tick would keep talking to storage —
// taking and releasing issuance leases — for minutes after the process was told
// to go, and outlive the wait meant to bound it.
func (m *Manager) tickContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	if m.stopCh == nil {
		return ctx, cancel
	}
	// The goroutine ends with the context either way, so it cannot outlive the
	// work it is guarding.
	go func() {
		select {
		case <-m.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// flushTimeout bounds one pass over the held chains. Generous enough for a
// sizeable backlog at one write each, short enough that it cannot become the
// tick.
const flushTimeout = 2 * time.Minute

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
	// Held chains first, on their OWN budget. Sharing the tick's context would
	// let a storage outage — the only way chains pile up — eat the deadline that
	// the renewals and the follower refresh below depend on.
	flushCtx, cancelFlush := m.tickContext(flushTimeout)
	stored := m.flushHeldChains(flushCtx)
	cancelFlush()

	// Read AFTER the flush, never before: the flush can run for minutes against
	// degraded storage, and leadership decides everything below — including
	// whether this node may publish to the shared index at all.
	leader := m.isLeader()

	ctx, cancel := m.tickContext(issueTimeout + 30*time.Second)
	defer cancel()

	m.announceStoredChains(ctx, leader, stored)

	// One deadline PER DOMAIN, not one across all of them. Under a shared
	// deadline a slow first domain leaves the last with seconds, and every
	// "context deadline exceeded" it then reports is charged to that domain's
	// retry budget for a problem that was ours — the same reasoning the
	// on-demand loop below was already built on.
	for _, domain := range m.domains {
		func() {
			dctx, dcancel := m.tickContext(issueTimeout)
			defer dcancel()
			if leader {
				m.reconcileCeremony(dctx, domain)
				if err := m.renewIfNeeded(dctx, domain); err != nil {
					m.logger.Warn("TLS: maintenance issue/renew failed", "domain", domain, "error", err)
				}
				return
			}
			if _, err := m.certCache.Refresh(dctx, domain); err != nil {
				m.logger.Debug("TLS: follower refresh found no certificate yet", "domain", domain, "error", err)
			}
		}()
	}

	// Its own deadline, not the one the loop above just spent: with a domain
	// per context that outer budget can be long gone by now, and a drift alarm
	// running on a dead context does not fail — it silently reports nothing,
	// which is the one thing an alarm must never do.
	daneCtx, daneCancel := m.tickContext(issueTimeout)
	defer daneCancel()

	// Drift alarm: leader-only so a mismatch alerts once, not once per node.
	if m.dane != nil && leader {
		m.dane.cleanupExpiredRetiring(daneCtx)
		for host, ok := range m.dane.verifyPublished(daneCtx) {
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
	// A publication that failed earlier is owed before anything else: until it
	// lands, every hostname it covers is one no follower will refresh.
	if err := m.onDemand.republishIndexIfDirty(loadCtx); err != nil {
		m.logger.Warn("TLS: could not republish the on-demand index", "error", err)
	}
	for _, host := range hosts {
		_, have := m.certCache.leafNotAfter(host)
		_, known := m.onDemand.indexNotAfter(host)
		if have {
			// Holding a certificate the index does not name. Three ways in: a
			// flush that adopted a chain already in storage, a handshake that
			// loaded one, or a node that stored a chain while demoted and could
			// not announce it. None of them pass through issuance, so none of
			// them would ever reach the announcement at the end of a run, and
			// the hostname would stay invisible to every follower until it
			// expired. Say it now — the leader is the only one who may.
			// Held but unstored is exactly what must NOT be announced: the
			// index says what storage holds, and a follower that believed this
			// entry would adopt the older chain still in storage, record itself
			// current at the announced expiry, and never see a difference again
			// when the real write finally lands. The flush announces it, once
			// storage actually has it.
			if !known && !m.certCache.isPending(host) {
				m.recordIssued(loadCtx, host)
			}
			continue
		}
		if !known {
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
		// Last look before spending money. This hostname was classified as a
		// FIRST issuance because neither memory nor the index mentioned it —
		// but the index records what a leader announced, not what storage
		// holds, and the two come apart: a chain flushed by a node that had
		// lost leadership cannot be announced at all, and an index write can
		// simply fail. Either way the certificate is sitting in storage and
		// the index does not say so, and the old cost of being wrong here was
		// a duplicate order for a certificate we already owned.
		//
		// One GET, bounded by the new-order budget below, against one order.
		// Adopting also republishes the index through the tail of this
		// function, which is what finally tells the followers it exists.
		if !isRenewal {
			if _, err := m.certCache.Refresh(ctx, host); err == nil {
				m.logger.Info("TLS: storage already held a certificate the index did not mention — adopting it instead of ordering", "domain", host)
				isRenewal = true
			}
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
		m.recordIssued(ctx, host)
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

// announceStoredChains publishes a late write to the on-demand index.
//
// An on-demand hostname reaches followers only through that index: they refresh
// what changedSince reports and nothing else. The leader will not revisit the
// hostname either — memory already holds a fresh certificate for it, so neither
// the classifier nor the handshake path will touch it again — so without this
// the chain sits in storage that no follower is ever told to read, until it
// expires. Static domains need none of it: followers re-read them every tick.
func (m *Manager) announceStoredChains(ctx context.Context, leader bool, stored []string) {
	if !leader || m.onDemand == nil {
		return
	}
	for _, domain := range stored {
		if m.domainSet[domain] {
			continue
		}
		m.recordIssued(ctx, domain)
	}
}

// recordIssued publishes a hostname's expiry to the shared on-demand index.
//
// One function for both callers — the issuance path and the late flush —
// because the interesting part is the failure, and it went unmentioned on one
// of them for exactly as long as they were separate. Not retried here: the
// entry is in the in-memory index, so the next hostname this leader publishes
// carries it along. On a fleet with no other on-demand churn, it waits for one.
func (m *Manager) recordIssued(ctx context.Context, host string) {
	if m.onDemand == nil {
		return
	}
	notAfter, ok := m.certCache.leafNotAfter(host)
	if !ok {
		return
	}
	if err := m.onDemand.noteIssued(ctx, host, notAfter); err != nil {
		m.logger.Warn("TLS: could not publish the on-demand index — followers will not refresh this hostname yet",
			"domain", host, "error", err)
	}
}

// flushHeldChains writes the chains an earlier issuance could not persist, and
// returns the domains it managed to store.
//
// Every guard here exists because this writes a shared object for a domain this
// node may no longer be responsible for:
//
//   - the per-domain inflight lock, so a handshake-driven issuance in this
//     process cannot land between the read below and the write;
//   - the issuance lease, so a peer flushing or issuing the same domain cannot
//     either — two nodes each holding a chain would otherwise race, and the
//     older one could land last;
//   - a read that must SUCCEED before writing. Storage holding something at
//     least as new means our copy is spent history, and a read that merely
//     failed proves nothing — treating "I could not look" as "nothing is
//     there" is how an older chain lands on top of a newer one.
//
// One attempt per domain per tick; the tick is the retry.
func (m *Manager) flushHeldChains(ctx context.Context) []string {
	held := m.certCache.pendingSnapshot()
	if len(held) == 0 {
		return nil
	}

	var stored []string
	for domain, p := range held {
		if ctx.Err() != nil {
			break
		}
		if m.flushOne(ctx, domain, p) {
			stored = append(stored, domain)
		}
	}
	return stored
}

// errStoredChainUnparseable marks a stored object that was read but is not a
// chain. Distinct from a read failure because it means the opposite: we know
// what storage holds, and it is worthless, so ours is safe to write over.
var errStoredChainUnparseable = errors.New("tls: stored chain could not be parsed")

// flushOne is one domain's flush, split out so the lock and lease releases are
// plain defers rather than a hand-unwound loop body.
func (m *Manager) flushOne(ctx context.Context, domain string, p pendingPersist) bool {
	// tryLock, not lock: the holder is an issuance or an operator's renewal for
	// this same domain, whose result supersedes what we hold — and it keeps the
	// mutex across a whole ACME order, which would park the flush well past its
	// own deadline and delay every domain queued behind it.
	unlock, free := m.inflight.tryLock(domain)
	if !free {
		m.logger.Debug("TLS: not flushing a held chain — issuance in progress for it", "domain", domain)
		return false
	}
	defer unlock()

	release, ok := m.acquireIssueLease(ctx, domain)
	if !ok {
		m.logger.Debug("TLS: not flushing a held chain — another node holds the lease", "domain", domain)
		return false
	}
	defer release()

	switch notAfter, err := m.certCache.storedNotAfter(ctx, domain); {
	case err == nil && !notAfter.Before(p.notAfter):
		// Storage moved on without us. Take what is there BEFORE letting go of
		// what we hold: leaving the older chain in memory would keep this node
		// serving a superseded SPKI, which after a peer's key replacement is a
		// DANE failure rather than a stale certificate. If the adoption fails —
		// a half-finished ceremony elsewhere reads as ErrKeyCertMismatch — keep
		// holding, so the next tick tries again instead of stranding memory on
		// the old chain with nothing left to notice it.
		if _, rerr := m.certCache.Refresh(ctx, domain); rerr != nil {
			m.logger.Warn("TLS: storage is ahead but its chain could not be adopted — holding on and retrying next tick",
				"domain", domain, "error", rerr)
			return false
		}
		m.logger.Info("TLS: storage holds a chain at least as new — dropping the held copy", "domain", domain)
		m.certCache.dropPending(domain)
		return false
	case err == nil:
		// Storage is behind ours — write.
	case errors.Is(err, os.ErrNotExist):
		// Storage has nothing — write.
	case errors.Is(err, errStoredChainUnparseable):
		// Storage holds something that is not a chain. Read, not guessed: ours
		// is unambiguously better, and refusing here would strand the domain
		// until an operator deleted the object by hand.
		m.logger.Warn("TLS: the stored chain is unreadable — replacing it with the held one", "domain", domain)
	default:
		m.logger.Warn("TLS: cannot check what storage holds — leaving the held chain alone", "domain", domain, "error", err)
		return false
	}

	if err := m.certCache.persist(ctx, domain, p.chainPEM, 1); err != nil {
		m.logger.Warn("TLS: still cannot store the issued chain — it stays in memory only", "domain", domain, "error", err)
		return false
	}
	m.logger.Info("TLS: stored a chain that had been held in memory since issuance", "domain", domain)
	// The attempts that failed were charged to the retry budget to stop an
	// automatic re-order; the chain is stored now, so leaving the domain
	// throttled for the rest of the hour would punish it for a problem that is
	// over.
	m.retries.reset(domain)
	m.certCache.dropPending(domain)
	return true
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
		// The soak record may be missing: ActivateCertificateKey writes it just
		// before promoting, and the storage failure that interrupted the
		// ceremony is just as able to have taken that write with it. Recorded
		// here while the live key is still the OLD one — after the promotion
		// below there is nothing left to read it from. Only when absent: a
		// second write would restart the soak window the operator is counting.
		if m.dane != nil && m.dane.isMX(domain) {
			if _, ok := m.dane.getRetiring(ctx, domain); !ok {
				if err := m.dane.markRetiring(ctx, domain); err != nil {
					m.logger.Warn("TLS: failed to record retiring DANE digest while completing the ceremony", "domain", domain, "error", err)
				}
			}
		}
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
	if _, err := m.issueWithKey(ctx, domain, certKey, false); err != nil {
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

	// An earlier attempt may have got a chain from the CA and failed to store
	// it. Re-ordering here is what an operator re-running the command after a
	// storage failure would cause, and the CA charges for it either way — five
	// duplicates a week is not many to spend on the same key twice.
	chainPEM, held, reused := m.certCache.heldChainFor(domain, nextKey)
	if reused {
		m.logger.Warn("TLS: reusing the certificate a previous activation ordered but could not store", "domain", domain, "not_after", held.Leaf.NotAfter)
	} else {
		issuer, ierr := m.ensureIssuer(ctx)
		if ierr != nil {
			return ierr
		}
		chainPEM, err = issuer.Issue(ctx, domain, nextKey)
		if err != nil {
			return fmt.Errorf("issue cert with next key for %s: %w", domain, err)
		}
	}
	// Serve the new cert (bound to the next key) before promoting, so storage and
	// the live key converge; PromoteNextCertKey then makes keyFor match the chain.
	cert, err := m.certCache.Store(ctx, domain, chainPEM, nextKey)
	heldNotStored := err != nil && cert != nil && errors.Is(err, errPersistFailed)
	if err != nil && !heldNotStored {
		return fmt.Errorf("store cert for %s: %w", domain, err)
	}
	// Record the OUTGOING (still-live) digest for the DANE soak window BEFORE
	// promoting, so the operator keeps the old TLSA record published until lagging
	// nodes converge on the new cert.
	// Only when absent. Re-running an activation is an ordinary flow now that a
	// held order is reused, and a second write would push RetireAfter forward —
	// restarting the soak the operator is counting down, on a digest that has
	// been retiring since the first attempt.
	if m.dane != nil && m.dane.isMX(domain) {
		if _, recorded := m.dane.getRetiring(ctx, domain); !recorded {
			if err := m.dane.markRetiring(ctx, domain); err != nil {
				m.logger.Warn("TLS: failed to record retiring DANE digest", "domain", domain, "error", err)
			}
		}
	}
	if heldNotStored {
		// The ceremony's order is as spent as any other, so hold the chain
		// rather than lose it. The key stays STAGED: promoting against a chain
		// storage does not have would leave every follower unable to pair them.
		// Once the flush lands the chain, reconcileCeremony promotes — the same
		// roll-forward that covers a leader crashing between Store and Promote.
		m.certCache.hold(domain, cert, chainPEM)
		return fmt.Errorf("%w for %s: the replacement key stays staged and the ceremony completes once storage accepts the chain: %v",
			ErrOrderNotPersisted, domain, err)
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
