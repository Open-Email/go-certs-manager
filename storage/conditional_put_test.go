package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
