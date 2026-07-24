package certmanager

import (
	"strings"
	"sync"
	"time"
)

// retryBudgetWindow is the sliding window over which failed issuance attempts
// are counted. It matches the period of Let's Encrypt's "failed validations per
// hostname" limit, so the budget maps directly onto the CA's own accounting.
const retryBudgetWindow = time.Hour

// retryBudget caps failed ACME issuance attempts per domain over a sliding
// one-hour window. Let's Encrypt allows 5 failed validations per hostname per
// hour; staying under that keeps a persistent local failure (firewall, DNS,
// storage) from exhausting the CA-side budget, so recovery is immediate once
// the root cause is fixed instead of being rate-limited for up to an hour.
//
// Only FAILED attempts consume budget: a domain that issues successfully on the
// first try is never throttled, and a success clears any accumulated failures.
type retryBudget struct {
	max int
	now func() time.Time // injectable for tests

	mu       sync.Mutex
	failures map[string][]time.Time // domain -> failure times within the window
}

func newRetryBudget(max int) *retryBudget {
	return &retryBudget{
		max:      max,
		now:      time.Now,
		failures: make(map[string][]time.Time),
	}
}

// allow reports whether another issuance attempt may run for domain. When the
// budget is exhausted it returns false and how long until the oldest failure
// ages out of the window (i.e. when the next attempt becomes allowed).
// A nil budget never throttles (hand-built Managers in tests), mirroring the
// nil-safe issuance lease.
func (b *retryBudget) allow(domain string) (time.Duration, bool) {
	if b == nil {
		return 0, true
	}
	domain = strings.ToLower(domain)
	b.mu.Lock()
	defer b.mu.Unlock()
	recent := b.prune(domain)
	if len(recent) < b.max {
		return 0, true
	}
	return recent[0].Add(retryBudgetWindow).Sub(b.now()), false
}

// recordFailure counts a failed issuance attempt against domain's budget.
func (b *retryBudget) recordFailure(domain string) {
	if b == nil {
		return
	}
	domain = strings.ToLower(domain)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures[domain] = append(b.prune(domain), b.now())
}

// reset clears domain's budget after a successful issuance.
func (b *retryBudget) reset(domain string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.failures, strings.ToLower(domain))
}

// prune drops failures older than the window and returns what remains, oldest
// first. Caller holds mu.
func (b *retryBudget) prune(domain string) []time.Time {
	cutoff := b.now().Add(-retryBudgetWindow)
	var kept []time.Time
	for _, t := range b.failures[domain] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(b.failures, domain)
	} else {
		b.failures[domain] = kept
	}
	return kept
}
