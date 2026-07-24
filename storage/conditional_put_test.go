// Provenance: originally smtp-in pkg/storage, hardened in openemail/filter
// (IfMatch CAS, os.ErrNotExist 404 contract, contract test) and upstreamed here.

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

// Two racing create-once writers must NOT both succeed — exactly one wins and the
// rest observe ConditionalPutError. This is what guarantees a single per-domain key
// (and ACME account key) across the cluster, which DANE depends on.
func TestFilesystemBackend_ConditionalPutIsAtomic(t *testing.T) {
	b, err := NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	const writers = 32
	var success, conflicts int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // maximize contention
			data := []byte(fmt.Sprintf("writer-%d", i))
			err := b.PutObject(context.Background(), "keys/mx.example.com", bytes.NewReader(data), int64(len(data)), PutOptions{IfNoneMatch: "*"})
			if err == nil {
				atomic.AddInt32(&success, 1)
				return
			}
			var ce *ConditionalPutError
			if errors.As(err, &ce) {
				atomic.AddInt32(&conflicts, 1)
				return
			}
			t.Errorf("unexpected error: %v", err)
		}(i)
	}
	close(start)
	wg.Wait()

	if success != 1 {
		t.Fatalf("expected exactly 1 successful create, got %d (conflicts=%d)", success, conflicts)
	}
	if conflicts != writers-1 {
		t.Fatalf("expected %d conflicts, got %d", writers-1, conflicts)
	}
}

// put writes data at key with opts, failing the test on error unless a
// *ConditionalPutError is expected by the caller (who then inspects the return).
func put(t *testing.T, b *FilesystemBackend, key string, data string, opts PutOptions) error {
	t.Helper()
	return b.PutObject(context.Background(), key, bytes.NewReader([]byte(data)), int64(len(data)), opts)
}

// TestFilesystemBackend_IfMatch pins the IfMatch CAS semantics the trainer's
// CURRENT-pointer publish relies on (SPEC2 §3): a put with the current ETag
// replaces the object; a stale or missing ETag target yields
// *ConditionalPutError and leaves the object untouched.
func TestFilesystemBackend_IfMatch(t *testing.T) {
	const key = "models/CURRENT"

	tests := []struct {
		name string
		// setup returns the IfMatch value to put with.
		setup        func(t *testing.T, b *FilesystemBackend) string
		wantConflict bool
		wantContent  string // expected object content after the put ("" = object absent)
	}{
		{
			name: "matching etag replaces",
			setup: func(t *testing.T, b *FilesystemBackend) string {
				if err := put(t, b, key, "v1", PutOptions{}); err != nil {
					t.Fatal(err)
				}
				info, err := b.StatObject(context.Background(), key)
				if err != nil {
					t.Fatal(err)
				}
				return info.ETag
			},
			wantConflict: false,
			wantContent:  "v2",
		},
		{
			name: "stale etag conflicts and preserves object",
			setup: func(t *testing.T, b *FilesystemBackend) string {
				if err := put(t, b, key, "v1", PutOptions{}); err != nil {
					t.Fatal(err)
				}
				info, err := b.StatObject(context.Background(), key)
				if err != nil {
					t.Fatal(err)
				}
				stale := info.ETag
				// A concurrent writer replaces the object; the ETag we hold
				// is now stale. The mtime-derived ETag changes because the
				// new temp file is written at a later nanosecond.
				if err := put(t, b, key, "concurrent", PutOptions{}); err != nil {
					t.Fatal(err)
				}
				if cur, err := b.StatObject(context.Background(), key); err != nil {
					t.Fatal(err)
				} else if cur.ETag == stale {
					t.Skip("filesystem mtime granularity too coarse to distinguish writes")
				}
				return stale
			},
			wantConflict: true,
			wantContent:  "concurrent",
		},
		{
			name: "missing object conflicts",
			setup: func(t *testing.T, b *FilesystemBackend) string {
				return "0123456789abcdef0123456789abcdef"
			},
			wantConflict: true,
			wantContent:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewFilesystemBackend(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			etag := tt.setup(t, b)

			putErr := put(t, b, key, "v2", PutOptions{IfMatch: etag})
			if tt.wantConflict {
				var ce *ConditionalPutError
				if !errors.As(putErr, &ce) {
					t.Fatalf("expected *ConditionalPutError, got %v", putErr)
				}
			} else if putErr != nil {
				t.Fatalf("expected success, got %v", putErr)
			}

			rc, err := b.GetObject(context.Background(), key)
			if tt.wantContent == "" {
				if err == nil {
					rc.Close()
					t.Fatal("expected object to remain absent")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(rc); err != nil {
				t.Fatal(err)
			}
			if buf.String() != tt.wantContent {
				t.Errorf("object content = %q; want %q", buf.String(), tt.wantContent)
			}
		})
	}
}

// TestFilesystemBackend_IfMatchIsAtomic races many CAS writers holding the
// SAME captured ETag: exactly one may win (its rename invalidates the ETag),
// everyone else must observe ConditionalPutError. This is the split-brain
// defense on the trainer's CURRENT pointer.
func TestFilesystemBackend_IfMatchIsAtomic(t *testing.T) {
	b, err := NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	const key = "models/CURRENT"
	if err := put(t, b, key, "v1", PutOptions{}); err != nil {
		t.Fatal(err)
	}
	info, err := b.StatObject(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}

	const writers = 16
	var success, conflicts int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // maximize contention
			data := fmt.Sprintf("writer-%d", i)
			err := put(t, b, key, data, PutOptions{IfMatch: info.ETag})
			if err == nil {
				atomic.AddInt32(&success, 1)
				return
			}
			var ce *ConditionalPutError
			if errors.As(err, &ce) {
				atomic.AddInt32(&conflicts, 1)
				return
			}
			t.Errorf("unexpected error: %v", err)
		}(i)
	}
	close(start)
	wg.Wait()

	if success != 1 {
		t.Fatalf("expected exactly 1 successful CAS, got %d (conflicts=%d)", success, conflicts)
	}
	if conflicts != writers-1 {
		t.Fatalf("expected %d conflicts, got %d", writers-1, conflicts)
	}
}

// TestFilesystemBackend_RemoveNeverResurrectsConditionalPut races RemoveObject
// against an IfMatch put holding the pre-delete ETag (the reset-vs-publish
// race on CURRENT). Because both serialize on fsCondPutMu, only two orders
// exist — put-then-remove (put wins, remove deletes) and remove-then-put (CAS
// fails on the missing object) — so the object must be ABSENT after both
// finish. Without the lock the delete could land between the put's ETag
// compare and its rename, resurrecting the deleted key. Run with -race.
func TestFilesystemBackend_RemoveNeverResurrectsConditionalPut(t *testing.T) {
	b, err := NewFilesystemBackend(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	const key = "models/CURRENT"

	for i := 0; i < 200; i++ {
		if err := put(t, b, key, "v1", PutOptions{}); err != nil {
			t.Fatal(err)
		}
		info, err := b.StatObject(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		go func() {
			defer wg.Done()
			<-start
			err := put(t, b, key, "resurrected?", PutOptions{IfMatch: info.ETag})
			var ce *ConditionalPutError
			if err != nil && !errors.As(err, &ce) {
				t.Errorf("iteration %d: conditional put failed unexpectedly: %v", i, err)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := b.RemoveObject(context.Background(), key); err != nil {
				t.Errorf("iteration %d: RemoveObject: %v", i, err)
			}
		}()
		close(start)
		wg.Wait()

		if _, err := b.StatObject(context.Background(), key); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("iteration %d: object resurrected after remove raced a conditional put (stat err = %v)", i, err)
		}
	}
}
