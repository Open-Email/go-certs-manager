package certmanager

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/storage"
)

func TestDANEController_RolloverRecords(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, nil, nil)
	ctl := newDANEController(ks, backend, "", []string{"mx.example.com"}, 3600, time.Minute, nil)
	ctx := context.Background()

	// No key yet -> no records.
	if recs, err := ctl.DesiredRecords(ctx); err != nil || len(recs) != 0 {
		t.Fatalf("expected 0 records before issuance, got %d (err %v)", len(recs), err)
	}

	// Live key created -> exactly one 3 1 1 record.
	liveKey, err := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	liveDigest, _ := dane.SPKISHA256(liveKey.Public())

	recs, err := ctl.DesiredRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].RData() != "3 1 1 "+liveDigest {
		t.Fatalf("unexpected rdata %q", recs[0].RData())
	}
	if recs[0].Name != "_25._tcp.mx.example.com." {
		t.Fatalf("unexpected owner %q", recs[0].Name)
	}

	// Ceremony staged -> current + next digests pre-published.
	nextKey, err := ks.GenerateNextCertKey(ctx, "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	nextDigest, _ := dane.SPKISHA256(nextKey.Public())

	recs, err = ctl.DesiredRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records during rollover, got %d", len(recs))
	}
	got := map[string]bool{recs[0].Cert: true, recs[1].Cert: true}
	if !got[liveDigest] || !got[nextDigest] {
		t.Fatalf("rollover records missing a digest: live=%s next=%s got=%v", liveDigest, nextDigest, got)
	}

	// Promote -> only the new digest remains.
	if err := ks.PromoteNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	recs, err = ctl.DesiredRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record after promotion, got %d", len(recs))
	}
	if recs[0].Cert != nextDigest {
		t.Fatalf("after promotion expected new digest %s, got %s", nextDigest, recs[0].Cert)
	}
}

func TestDANEController_RetiringSoak(t *testing.T) {
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return true }, nil)
	ctl := newDANEController(ks, backend, "", []string{"mx.example.com"}, 3600, time.Minute, nil)
	ctx := context.Background()

	// Establish a live key, then mark it retiring (as Activate does, before promote),
	// then promote a new key so the live digest differs from the retiring one.
	oldKey, _ := ks.LoadOrCreateCertKey(ctx, "mx.example.com")
	oldDigest, _ := dane.SPKISHA256(oldKey.Public())
	if err := ctl.markRetiring(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.GenerateNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := ks.PromoteNextCertKey(ctx, "mx.example.com"); err != nil {
		t.Fatal(err)
	}
	newKey, _ := ks.LoadCertKey(ctx, "mx.example.com")
	newDigest, _ := dane.SPKISHA256(newKey.Public())

	recs, err := ctl.DesiredRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Expect the new (live) digest AND the retiring old digest with a note.
	var sawLive, sawRetiring bool
	for _, r := range recs {
		switch r.Cert {
		case newDigest:
			sawLive = true
		case oldDigest:
			sawRetiring = true
			if r.Note == "" {
				t.Fatal("retiring record missing the keep-until note")
			}
		}
	}
	if !sawLive || !sawRetiring {
		t.Fatalf("expected live+retiring records; live=%v retiring=%v (n=%d)", sawLive, sawRetiring, len(recs))
	}

	// Force the soak to elapse by overwriting the marker with a past deadline.
	expired, _ := json.Marshal(dane.RetiringRecord{Digest: oldDigest, RetireAfter: time.Now().Add(-time.Hour).Unix()})
	key := dane.RetiringObjectName("", "mx.example.com")
	if err := backend.PutObject(ctx, key, strings.NewReader(string(expired)), int64(len(expired)), storage.PutOptions{}); err != nil {
		t.Fatal(err)
	}

	recs, _ = ctl.DesiredRecords(ctx)
	for _, r := range recs {
		if r.Cert == oldDigest {
			t.Fatal("expired retiring digest should no longer be published")
		}
	}

	// Leader cleanup removes the expired marker.
	ctl.cleanupExpiredRetiring(ctx)
	if _, ok := ctl.getRetiring(ctx, "mx.example.com"); ok {
		t.Fatal("expired retiring marker should have been cleaned up")
	}
}

// fakeLookup returns a TLSALookup with a fixed answer.
func fakeLookup(res dane.LookupResult, err error) dane.TLSALookup {
	return func(context.Context, string) (dane.LookupResult, error) { return res, err }
}

func publishedEE(digests ...string) dane.LookupResult {
	res := dane.LookupResult{Authenticated: true}
	for _, d := range digests {
		res.RRs = append(res.RRs, dane.PublishedTLSA{Usage: 3, Selector: 1, MatchingType: 1, Cert: d})
	}
	return res
}

func newVerifyController(t *testing.T) (*daneController, *KeyStore, string) {
	t.Helper()
	backend, err := storage.NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ks := NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return true }, nil)
	ctl := newDANEController(ks, backend, "", []string{"mx.example.com"}, 3600, time.Minute, nil)
	key, err := ks.LoadOrCreateCertKey(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dane.SPKISHA256(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return ctl, ks, digest
}

func TestDANEController_VerifyPublished(t *testing.T) {
	ctx := context.Background()

	t.Run("match", func(t *testing.T) {
		ctl, _, digest := newVerifyController(t)
		ctl.lookup = fakeLookup(publishedEE(digest), nil)
		status := ctl.verifyPublished(ctx)
		if ok, present := status["mx.example.com"]; !present || !ok {
			t.Fatalf("expected match, got %v", status)
		}
	})

	t.Run("missing desired record is drift", func(t *testing.T) {
		ctl, _, _ := newVerifyController(t)
		ctl.lookup = fakeLookup(publishedEE(strings.Repeat("ab", 32)), nil)
		if ok := ctl.verifyPublished(ctx)["mx.example.com"]; ok {
			t.Fatal("expected drift when the live digest is not published")
		}
	})

	t.Run("unknown published record is drift", func(t *testing.T) {
		ctl, _, digest := newVerifyController(t)
		ctl.lookup = fakeLookup(publishedEE(digest, strings.Repeat("cd", 32)), nil)
		if ok := ctl.verifyPublished(ctx)["mx.example.com"]; ok {
			t.Fatal("expected drift when an unknown 3 1 1 record is published")
		}
	})

	t.Run("nothing published is drift", func(t *testing.T) {
		ctl, _, _ := newVerifyController(t)
		ctl.lookup = fakeLookup(dane.LookupResult{}, nil)
		if ok, present := ctl.verifyPublished(ctx)["mx.example.com"]; !present || ok {
			t.Fatal("expected drift when nothing is published")
		}
	})

	t.Run("lookup failure omits the host", func(t *testing.T) {
		ctl, _, _ := newVerifyController(t)
		ctl.lookup = fakeLookup(dane.LookupResult{}, context.DeadlineExceeded)
		if _, present := ctl.verifyPublished(ctx)["mx.example.com"]; present {
			t.Fatal("indeterminate lookup must not report a status")
		}
	})

	t.Run("nil lookup disables verification", func(t *testing.T) {
		ctl, _, _ := newVerifyController(t)
		if status := ctl.verifyPublished(ctx); status != nil {
			t.Fatalf("expected nil status, got %v", status)
		}
	})
}

func TestDANEController_GateIssuance(t *testing.T) {
	ctx := context.Background()

	t.Run("existing key with published match allows", func(t *testing.T) {
		ctl, _, digest := newVerifyController(t)
		ctl.lookup = fakeLookup(publishedEE(digest), nil)
		if err := ctl.gateIssuance(ctx, "mx.example.com"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("existing key with mismatch still allows (SPKI-neutral)", func(t *testing.T) {
		ctl, _, _ := newVerifyController(t)
		ctl.lookup = fakeLookup(publishedEE(strings.Repeat("ab", 32)), nil)
		if err := ctl.gateIssuance(ctx, "mx.example.com"); err != nil {
			t.Fatalf("renewal reuses the key and must not be blocked: %v", err)
		}
	})

	t.Run("missing key with published DANE-EE blocks", func(t *testing.T) {
		backend, _ := storage.NewFilesystemBackend(t.TempDir(), nil)
		ks := NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return true }, nil)
		ctl := newDANEController(ks, backend, "", []string{"mx.example.com"}, 3600, time.Minute, nil)
		ctl.lookup = fakeLookup(publishedEE(strings.Repeat("ab", 32)), nil)
		err := ctl.gateIssuance(ctx, "mx.example.com")
		if err == nil || !strings.Contains(err.Error(), "no live key exists") {
			t.Fatalf("expected blocking error, got %v", err)
		}
	})

	t.Run("missing key with nothing published allows bootstrap", func(t *testing.T) {
		backend, _ := storage.NewFilesystemBackend(t.TempDir(), nil)
		ks := NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return true }, nil)
		ctl := newDANEController(ks, backend, "", []string{"mx.example.com"}, 3600, time.Minute, nil)
		ctl.lookup = fakeLookup(dane.LookupResult{}, nil)
		if err := ctl.gateIssuance(ctx, "mx.example.com"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing key with lookup failure fails open", func(t *testing.T) {
		backend, _ := storage.NewFilesystemBackend(t.TempDir(), nil)
		ks := NewKeyStore(backend, "", KeyTypeECDSAP256, func() bool { return true }, nil)
		ctl := newDANEController(ks, backend, "", []string{"mx.example.com"}, 3600, time.Minute, nil)
		ctl.lookup = fakeLookup(dane.LookupResult{}, context.DeadlineExceeded)
		if err := ctl.gateIssuance(ctx, "mx.example.com"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("non-MX host is never gated", func(t *testing.T) {
		ctl, _, _ := newVerifyController(t)
		ctl.lookup = func(context.Context, string) (dane.LookupResult, error) {
			t.Fatal("lookup must not run for non-MX hosts")
			return dane.LookupResult{}, nil
		}
		if err := ctl.gateIssuance(ctx, "submission.example.com"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("nil controller and nil lookup allow", func(t *testing.T) {
		var nilCtl *daneController
		if err := nilCtl.gateIssuance(ctx, "mx.example.com"); err != nil {
			t.Fatal(err)
		}
		ctl, _, _ := newVerifyController(t)
		ctl.lookup = nil
		if err := ctl.gateIssuance(ctx, "mx.example.com"); err != nil {
			t.Fatal(err)
		}
	})
}
