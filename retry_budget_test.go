package certmanager

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

// fakeClock drives a retryBudget deterministically.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestBudget(max int) (*retryBudget, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := newRetryBudget(max)
	b.now = clock.now
	return b, clock
}

func TestRetryBudgetAllowsUpToMax(t *testing.T) {
	b, _ := newTestBudget(3)

	for i := 0; i < 3; i++ {
		if _, ok := b.allow("smtp.example.com"); !ok {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
		b.recordFailure("smtp.example.com")
	}

	wait, ok := b.allow("smtp.example.com")
	if ok {
		t.Fatal("4th attempt within the window should be blocked")
	}
	if wait <= 0 || wait > retryBudgetWindow {
		t.Fatalf("wait should be within (0, 1h], got %s", wait)
	}
}

func TestRetryBudgetWindowSlides(t *testing.T) {
	b, clock := newTestBudget(3)

	// Two failures early, one 40 minutes later.
	b.recordFailure("smtp.example.com")
	b.recordFailure("smtp.example.com")
	clock.advance(40 * time.Minute)
	b.recordFailure("smtp.example.com")

	if _, ok := b.allow("smtp.example.com"); ok {
		t.Fatal("should be blocked with 3 failures in the last hour")
	}

	// 21 more minutes: the first two failures age out (61 min old), one remains.
	clock.advance(21 * time.Minute)
	if _, ok := b.allow("smtp.example.com"); !ok {
		t.Fatal("should be allowed once old failures age out of the window")
	}
}

func TestRetryBudgetResetOnSuccess(t *testing.T) {
	b, _ := newTestBudget(3)

	for i := 0; i < 3; i++ {
		b.recordFailure("smtp.example.com")
	}
	if _, ok := b.allow("smtp.example.com"); ok {
		t.Fatal("should be blocked before reset")
	}

	b.reset("smtp.example.com")
	if _, ok := b.allow("smtp.example.com"); !ok {
		t.Fatal("should be allowed after a successful issuance resets the budget")
	}
}

func TestRetryBudgetPerDomain(t *testing.T) {
	b, _ := newTestBudget(1)

	b.recordFailure("a.example.com")
	if _, ok := b.allow("a.example.com"); ok {
		t.Fatal("a.example.com should be blocked")
	}
	if _, ok := b.allow("b.example.com"); !ok {
		t.Fatal("b.example.com must not be affected by a.example.com's failures")
	}
}

func TestRetryBudgetCaseInsensitive(t *testing.T) {
	b, _ := newTestBudget(1)

	b.recordFailure("SMTP.Example.COM")
	if _, ok := b.allow("smtp.example.com"); ok {
		t.Fatal("domain matching must be case-insensitive")
	}
}

// An exhausted budget must short-circuit issueWithKey BEFORE any lease or CA
// interaction: the call returns a "retry budget exhausted" error without
// touching the network.
func TestIssueWithKeyRespectsRetryBudget(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, nil, nil)
	key, err := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		keyStore:    ks,
		certCache:   newCertCache(backend, "", ks.LoadCertKey, nil),
		logger:      slog.Default(),
		retries:     newRetryBudget(1),
		renewBefore: 30 * 24 * time.Hour,
	}
	m.retries.recordFailure("mx.example.com")

	if _, err := m.issueWithKey(ctx, "mx.example.com", key); err == nil ||
		!strings.Contains(err.Error(), "retry budget exhausted") {
		t.Fatalf("expected retry-budget error, got %v", err)
	}
}
