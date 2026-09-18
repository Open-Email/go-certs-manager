package certmanager

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/storage"
)

// onDemandLeader builds a leader with a dynamic allow-set over one backend.
func onDemandLeader(t *testing.T, backend storage.Backend, ca *countingCA, hosts ...string) *Manager {
	t.Helper()
	m := newOnDemandManager(t, backend, true, OnDemandConfig{MaxConcurrentOrders: 2})
	m.issuer = ca
	m.renewBefore = 30 * 24 * time.Hour
	m.retries = newRetryBudget(3)
	m.onDemand.store(hosts)
	return m
}

// A write that failed on our side but landed on the server's is the ordinary
// shape of a dropped connection. The next flush finds the chain already there
// and lets go of its copy — and that path announced nothing, so the hostname
// stayed invisible to every follower until it expired.
func TestFlushHeldChains_AnnouncesAChainItFindsAlreadyStored(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := onDemandLeader(t, fs, &countingCA{}, "vanity.example.com")

	cert := holdChain(t, m, "vanity.example.com", 61)
	// The PUT the node believes failed actually committed: storage has exactly
	// the chain still being held.
	storeHeldChain(t, m, "vanity.example.com")

	m.maintainOnce()

	if got := m.certCache.pendingDomains(); len(got) != 0 {
		t.Fatalf("still holding %v after storage turned out to have it", got)
	}
	notAfter, known := m.onDemand.indexNotAfter("vanity.example.com")
	if !known {
		t.Fatal("a chain found already stored was never announced; no follower will refresh it")
	}
	if !notAfter.Equal(cert.Leaf.NotAfter) {
		t.Fatalf("index says %v, certificate says %v", notAfter, cert.Leaf.NotAfter)
	}
}

// A handshake loads the certificate into memory. That alone used to be enough
// to hide the hostname from maintenance for good: in memory means it is neither
// a first issuance nor a renewal, so nothing ever looked at it again — and
// nothing announced it.
func TestMaintainOnDemand_AnnouncesWhatMemoryHoldsAndTheIndexDoesNot(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ca := &countingCA{}
	m := onDemandLeader(t, fs, ca, "vanity.example.com")

	// In memory and in storage, but never announced — a handshake got there
	// first, or a demoted node stored it.
	cert := holdChain(t, m, "vanity.example.com", 62)
	storeHeldChain(t, m, "vanity.example.com")
	m.certCache.dropPending("vanity.example.com")
	if _, known := m.onDemand.indexNotAfter("vanity.example.com"); known {
		t.Fatal("setup: the index should not know this hostname")
	}

	m.maintainOnDemand(true)

	if ca.orders != 0 {
		t.Fatalf("CA saw %d order(s) for a hostname already held, want 0", ca.orders)
	}
	notAfter, known := m.onDemand.indexNotAfter("vanity.example.com")
	if !known {
		t.Fatal("the leader holds a certificate the index does not name and never published it")
	}
	if !notAfter.Equal(cert.Leaf.NotAfter) {
		t.Fatalf("index says %v, certificate says %v", notAfter, cert.Leaf.NotAfter)
	}
}

// One dropped PUT on the index must not cost days of follower blindness. The
// publication is owed, and the next tick pays it.
func TestOnDemandIndex_RepublishesAfterAFailedWrite(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	backend := &flakyBackend{Backend: fs, failFor: certIndexKey, failPuts: 1}
	m := onDemandLeader(t, backend, &countingCA{}, "vanity.example.com")

	holdChain(t, m, "vanity.example.com", 63)
	if err := m.onDemand.noteIssued(ctx, "vanity.example.com", time.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("setup: the index write should have failed")
	}
	if _, err := readObject(ctx, backend, m.onDemand.key(certIndexKey)); err == nil {
		t.Fatal("setup: nothing should be published yet")
	}

	// A later tick, with no other hostname to carry it along.
	m.maintainOnDemand(true)

	body, err := readObject(ctx, backend, m.onDemand.key(certIndexKey))
	if err != nil {
		t.Fatalf("the index was never republished: %v", err)
	}
	if !strings.Contains(string(body), "vanity.example.com") {
		t.Fatalf("republished index does not name the hostname: %s", body)
	}
}

// The soak record says which TLSA record the operator must keep published. The
// storage failure that interrupts a ceremony takes that write with it just as
// readily as the chain's, and after the promotion there is no live old key left
// to reconstruct it from.
func TestReconcileCeremony_RecordsTheRetiringDigestTheInterruptionLost(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = fs
	m, ca, flaky := newFlakyManager(t, persistAttempts)
	// A real outage takes the DANE write with the chain write. Only the lease
	// keeps working, which is what lets the order happen at all.
	outage := &flakyBackend{Backend: flaky.Backend, failFor: "dane/retiring/", failPuts: persistAttempts}
	m.dane = newDANEController(m.keyStore, outage, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())

	liveBefore, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	oldDigest, err := dane.SPKISHA256(liveBefore.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}

	// Storage is down: the chain is held, and the soak record never lands.
	if err := m.ActivateCertificateKey("mx.example.com", true); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("err = %v, want ErrOrderNotPersisted", err)
	}
	if _, ok := soleRetiring(t, m, "mx.example.com"); ok {
		t.Fatal("setup: the retiring record should not have survived the outage")
	}

	// Storage recovers and the ceremony rolls forward.
	flaky.failPuts = 0
	outage.failPuts = 0
	if stored := m.flushHeldChains(ctx); len(stored) != 1 {
		t.Fatalf("flush stored %v, want the ceremony's chain", stored)
	}
	m.reconcileCeremony(ctx, "mx.example.com")

	rec, ok := soleRetiring(t, m, "mx.example.com")
	if !ok {
		t.Fatal("no retiring digest recorded; the old TLSA record gets dropped with no soak")
	}
	if rec.Digest != oldDigest {
		t.Fatalf("retiring digest = %s, want the outgoing key's %s", rec.Digest, oldDigest)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s), want 1", ca.orders)
	}
}

// Re-running an activation after a storage failure must not buy the same
// certificate twice: the first attempt's order is held, bound to the staged key.
func TestActivateCertificateKey_ReusesTheOrderItAlreadyPlaced(t *testing.T) {
	ctx := context.Background()
	m, ca, flaky := newFlakyManager(t, 100) // down for both attempts

	if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.ActivateCertificateKey("mx.example.com", true); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("first attempt: err = %v, want ErrOrderNotPersisted", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s) on the first attempt, want 1", ca.orders)
	}

	// The operator re-runs it while storage is still down.
	if err := m.ActivateCertificateKey("mx.example.com", true); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("second attempt: err = %v, want ErrOrderNotPersisted", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s) after a retry, want still 1 — the held order must be reused", ca.orders)
	}

	// And once storage recovers it completes, still on that one order.
	flaky.failPuts = 0
	if err := m.ActivateCertificateKey("mx.example.com", true); err != nil {
		t.Fatalf("third attempt: %v", err)
	}
	if ca.orders != 1 {
		t.Fatalf("CA saw %d order(s) in total, want 1", ca.orders)
	}
}

// The failures charged while storage was down stop mattering the moment the
// chain is stored; leaving the domain throttled punishes it for a problem that
// is over.
func TestFlushHeldChains_ClearsTheRetryBudgetItCharged(t *testing.T) {
	m, _, flaky := newFlakyManager(t, 100) // down throughout

	// Three forced renewals, each reaching the CA and failing to store: exactly
	// the budget, so the fourth attempt would be refused.
	for i := 0; i < 3; i++ {
		if _, err := m.RenewCertificate("mx.example.com"); !errors.Is(err, ErrOrderNotPersisted) {
			t.Fatalf("attempt %d: err = %v, want ErrOrderNotPersisted", i+1, err)
		}
	}
	if _, ok := m.retries.allow("mx.example.com"); ok {
		t.Fatal("setup: the budget should be exhausted after three failures")
	}

	ctx := context.Background()
	flaky.failPuts = 0
	if stored := m.flushHeldChains(ctx); len(stored) != 1 {
		t.Fatalf("flush stored %v, want [mx.example.com]", stored)
	}

	if _, ok := m.retries.allow("mx.example.com"); !ok {
		t.Error("the domain is still throttled after its chain was stored")
	}
}

// storeHeldChain writes the chain currently held for domain into storage,
// standing in for a PUT that landed on the server after the client gave up.
func storeHeldChain(t *testing.T, m *Manager, domain string) {
	t.Helper()
	held := m.certCache.pendingSnapshot()
	p, ok := held[strings.ToLower(domain)]
	if !ok {
		t.Fatalf("nothing held for %s", domain)
	}
	if err := m.certCache.persist(context.Background(), domain, p.chainPEM, 1); err != nil {
		t.Fatal(err)
	}
}

// The index says what STORAGE holds. Announcing a chain that is only in memory
// tells followers to adopt what is actually there — the older chain — and to
// record themselves current at the expiry we announced, after which the real
// write lands on the same value and their diff never fires again.
func TestMaintainOnDemand_DoesNotAnnounceAChainStorageDoesNotHaveYet(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := onDemandLeader(t, fs, &countingCA{}, "vanity.example.com")
	holdChain(t, m, "vanity.example.com", 71) // memory only; storage has nothing

	m.maintainOnDemand(true)

	if _, known := m.onDemand.indexNotAfter("vanity.example.com"); known {
		t.Fatal("announced a chain that is not in storage; followers would adopt something older and stop looking")
	}

	// Once it really is stored, it is announced.
	storeHeldChain(t, m, "vanity.example.com")
	m.certCache.dropPending("vanity.example.com")
	m.maintainOnDemand(true)

	if _, known := m.onDemand.indexNotAfter("vanity.example.com"); !known {
		t.Error("a stored chain was still not announced")
	}
}

// Re-running an activation must not restart the soak the operator is counting
// down. The digest has been retiring since the first attempt.
func TestActivateCertificateKey_DoesNotRestartTheSoakOnARetry(t *testing.T) {
	ctx := context.Background()
	m, _, flaky := newFlakyManager(t, 100) // storage down, so the first attempt holds
	m.dane = newDANEController(m.keyStore, flaky.Backend, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())

	if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.ActivateCertificateKey("mx.example.com", true); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("first attempt: err = %v, want ErrOrderNotPersisted", err)
	}
	first, ok := soleRetiring(t, m, "mx.example.com")
	if !ok {
		t.Fatal("setup: the first attempt should have recorded the retiring digest")
	}

	time.Sleep(1100 * time.Millisecond) // RetireAfter has one-second resolution
	if err := m.ActivateCertificateKey("mx.example.com", true); !errors.Is(err, ErrOrderNotPersisted) {
		t.Fatalf("second attempt: err = %v, want ErrOrderNotPersisted", err)
	}

	second, ok := soleRetiring(t, m, "mx.example.com")
	if !ok {
		t.Fatal("the retiring record disappeared on the retry")
	}
	if second.RetireAfter != first.RetireAfter {
		t.Errorf("soak restarted: RetireAfter moved from %d to %d", first.RetireAfter, second.RetireAfter)
	}
	if second.Digest != first.Digest {
		t.Errorf("retiring digest changed from %s to %s", first.Digest, second.Digest)
	}
}

// storedChain puts a certificate for host into both storage and memory, the
// state announcement is allowed from.
func storedChain(t *testing.T, m *Manager, host string, serial int64) *tls.Certificate {
	t.Helper()
	cert := holdChain(t, m, host, serial)
	storeHeldChain(t, m, host)
	m.certCache.dropPending(host)
	return cert
}

// A second rotation inside the first one's soak is not a retry, and not a
// replacement either. A→B then B→C leaves A-bound and B-bound chains both being
// served somewhere in the fleet, so BOTH digests have to stay published: keeping
// only one means an operator drops a TLSA record that nodes are still
// presenting, which is a DANE hard failure rather than a stale record.
func TestActivateCertificateKey_KeepsEveryRotationsRetiringDigest(t *testing.T) {
	ctx := context.Background()
	m, _, flaky := newFlakyManager(t, 0) // storage works: both ceremonies complete
	m.dane = newDANEController(m.keyStore, flaky.Backend, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())

	digestOf := func(what string) string {
		t.Helper()
		k, err := m.keyStore.LoadCertKey(ctx, "mx.example.com")
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		d, err := dane.SPKISHA256(k.Public())
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return d
	}
	rotate := func(what string) {
		t.Helper()
		if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if err := m.ActivateCertificateKey("mx.example.com", true); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	digestA := digestOf("A")
	rotate("A->B")
	digestB := digestOf("B")
	if digestB == digestA {
		t.Fatal("setup: the key did not actually rotate")
	}
	rotate("B->C")

	retiring := map[string]bool{}
	for _, rec := range mustRetiring(t, m, "mx.example.com") {
		retiring[rec.Digest] = true
	}
	if !retiring[digestA] {
		t.Error("A's digest was dropped by the second rotation; nodes still serving A-bound chains lose DANE")
	}
	if !retiring[digestB] {
		t.Error("B's digest was never recorded; the second rotation looked like a retry of the first")
	}

	// And both reach the records the operator is told to publish.
	records, err := m.dane.recordsForHost(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	published := map[string]bool{}
	for _, r := range records {
		published[r.Cert] = true
	}
	for name, digest := range map[string]string{"A": digestA, "B": digestB} {
		if !published[digest] {
			t.Errorf("%s's retiring digest is not in the records to publish", name)
		}
	}
}

// The guard belongs to the publish path itself, not to its callers: there are
// several, and the one that forgot is how this was found.
func TestRecordIssued_RefusesAChainStorageDoesNotHave(t *testing.T) {
	fs, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := onDemandLeader(t, fs, &countingCA{}, "vanity.example.com")
	holdChain(t, m, "vanity.example.com", 81) // memory only

	m.recordIssued(context.Background(), "vanity.example.com")

	if _, known := m.onDemand.indexNotAfter("vanity.example.com"); known {
		t.Fatal("recordIssued published a chain that is not in storage")
	}

	storeHeldChain(t, m, "vanity.example.com")
	m.certCache.dropPending("vanity.example.com")
	m.recordIssued(context.Background(), "vanity.example.com")

	if _, known := m.onDemand.indexNotAfter("vanity.example.com"); !known {
		t.Error("recordIssued refused a chain that IS in storage")
	}
}

// soleRetiring returns the one retiring record for a host, failing if there is
// not exactly one — the shape most of these tests are about.
func soleRetiring(t *testing.T, m *Manager, host string) (dane.RetiringRecord, bool) {
	t.Helper()
	recs, err := m.dane.retiring(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	switch len(recs) {
	case 0:
		return dane.RetiringRecord{}, false
	case 1:
		return recs[0], true
	default:
		t.Fatalf("%d retiring records for %s, expected one: %+v", len(recs), host, recs)
		return dane.RetiringRecord{}, false
	}
}

// Markers written before the list existed are in flight in exactly the
// situation that matters — mid-soak — so the old single-object form must still
// be read, and must survive being added to.
func TestRetiring_ReadsTheSingleObjectFormWrittenBeforeTheList(t *testing.T) {
	ctx := context.Background()
	m, _, flaky := newFlakyManager(t, 0)
	m.dane = newDANEController(m.keyStore, flaky.Backend, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())

	legacy := `{"digest":"aaaa","retire_after":` + strconv.FormatInt(time.Now().Add(12*time.Hour).Unix(), 10) + `}`
	key := dane.RetiringObjectName("", "mx.example.com")
	if err := flaky.Backend.PutObject(ctx, key, strings.NewReader(legacy), int64(len(legacy)),
		storage.PutOptions{ContentType: "application/json"}); err != nil {
		t.Fatal(err)
	}

	recs := mustRetiring(t, m, "mx.example.com")
	if len(recs) != 1 || recs[0].Digest != "aaaa" {
		t.Fatalf("legacy marker not read back: %+v", recs)
	}

	// A rotation now adds to it rather than replacing it.
	if _, err := m.keyStore.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := m.ActivateCertificateKey("mx.example.com", true); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, rec := range mustRetiring(t, m, "mx.example.com") {
		if rec.Digest == "aaaa" {
			found = true
		}
	}
	if !found {
		t.Error("the legacy digest was dropped by the first rotation after the upgrade")
	}
}

// An expired digest stops being published and is pruned, while an unexpired one
// beside it is left alone.
func TestCleanupExpiredRetiring_PrunesOnlyWhatHasElapsed(t *testing.T) {
	ctx := context.Background()
	m, _, flaky := newFlakyManager(t, 0)
	m.dane = newDANEController(m.keyStore, flaky.Backend, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())

	both := []dane.RetiringRecord{
		{Digest: "expired", RetireAfter: time.Now().Add(-time.Hour).Unix()},
		{Digest: "live", RetireAfter: time.Now().Add(time.Hour).Unix()},
	}
	body, err := json.Marshal(both)
	if err != nil {
		t.Fatal(err)
	}
	key := dane.RetiringObjectName("", "mx.example.com")
	if err := flaky.Backend.PutObject(ctx, key, strings.NewReader(string(body)), int64(len(body)),
		storage.PutOptions{ContentType: "application/json"}); err != nil {
		t.Fatal(err)
	}

	m.dane.cleanupExpiredRetiring(ctx)

	recs := mustRetiring(t, m, "mx.example.com")
	if len(recs) != 1 || recs[0].Digest != "live" {
		t.Fatalf("after cleanup: %+v, want only the unexpired digest", recs)
	}
}

// mustRetiring reads a host's retiring markers, failing the test on a read error.
func mustRetiring(t *testing.T, m *Manager, host string) []dane.RetiringRecord {
	t.Helper()
	recs, err := m.dane.retiring(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// A read that failed is not a host with no markers. Rebuilding the list from
// "nothing" would erase every digest recorded so far, which is the DANE hard
// failure the marker exists to prevent.
func TestMarkRetiring_RefusesToWriteWhenItCannotReadWhatIsThere(t *testing.T) {
	ctx := context.Background()
	m, _, flaky := newFlakyManager(t, 0)
	blind := &readErrorBackend{Backend: flaky.Backend, failGetFor: "dane/retiring/"}
	m.dane = newDANEController(m.keyStore, blind, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())

	// Something is already retiring.
	existing := []dane.RetiringRecord{
		{Digest: "aaaa", RetireAfter: time.Now().Add(12 * time.Hour).Unix()},
		{Digest: "bbbb", RetireAfter: time.Now().Add(12 * time.Hour).Unix()},
	}
	body, err := json.Marshal(existing)
	if err != nil {
		t.Fatal(err)
	}
	key := dane.RetiringObjectName("", "mx.example.com")
	if err := flaky.Backend.PutObject(ctx, key, strings.NewReader(string(body)), int64(len(body)),
		storage.PutOptions{ContentType: "application/json"}); err != nil {
		t.Fatal(err)
	}

	if err := m.dane.markRetiring(ctx, "mx.example.com"); err == nil {
		t.Fatal("markRetiring reported success though it could not read the existing markers")
	}
	if blind.puts != 0 {
		t.Fatalf("%d write(s) while the read was failing, want 0", blind.puts)
	}

	// Nothing was lost: a reader that can see storage still finds both.
	readable := newDANEController(m.keyStore, flaky.Backend, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())
	recs, err := readable.retiring(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("%d marker(s) survived, want 2: %+v", len(recs), recs)
	}
}

// The records the operator is told to publish must never quietly omit a
// retiring digest because storage would not answer.
func TestRecordsForHost_FailsRatherThanOmitUnreadableRetiringDigests(t *testing.T) {
	ctx := context.Background()
	m, _, flaky := newFlakyManager(t, 0)
	blind := &readErrorBackend{Backend: flaky.Backend, failGetFor: "dane/retiring/"}
	m.dane = newDANEController(m.keyStore, blind, "", []string{"mx.example.com"}, 3600, 24*time.Hour, testLogger())

	if _, err := m.dane.recordsForHost(ctx, "mx.example.com"); err == nil {
		t.Fatal("recordsForHost answered as though there were no retiring digests")
	}
}

// One digest keeps the shape a node on an older pin can read; the array appears
// only when the state genuinely needs it.
func TestMarshalRetiring_StaysReadableToOlderNodesWhileItCan(t *testing.T) {
	one := []dane.RetiringRecord{{Digest: "aaaa", RetireAfter: 123}}
	body, err := dane.MarshalRetiring(one)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		t.Fatalf("a single digest was written as %s; a node on an older pin cannot read that", body)
	}
	var legacy dane.RetiringRecord
	if err := json.Unmarshal(body, &legacy); err != nil || legacy.Digest != "aaaa" {
		t.Fatalf("an older reader cannot parse it: %v (%s)", err, body)
	}

	two := append(one, dane.RetiringRecord{Digest: "bbbb", RetireAfter: 456})
	body, err = dane.MarshalRetiring(two)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
		t.Fatalf("two digests must use the list form, got %s", body)
	}
	back, err := dane.ParseRetiring(body)
	if err != nil || len(back) != 2 {
		t.Fatalf("round trip lost entries: %+v (%v)", back, err)
	}
}

// An entry with no digest would become a malformed "3 1 1 " record and a drift
// warning that never clears.
func TestParseRetiring_DropsEntriesWithNoDigest(t *testing.T) {
	recs, err := dane.ParseRetiring([]byte(`[{"digest":"","retire_after":1},{"digest":"aaaa","retire_after":2}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Digest != "aaaa" {
		t.Fatalf("got %+v, want only the entry with a digest", recs)
	}
	if recs, err := dane.ParseRetiring([]byte(`{"digest":"","retire_after":1}`)); err != nil || len(recs) != 0 {
		t.Fatalf("got %+v (%v), want none", recs, err)
	}
}
