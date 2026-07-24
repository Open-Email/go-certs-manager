package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

// TestBackendContract pins the sentinel-error contract documented on the
// Backend interface — os.ErrNotExist for missing keys, *ConditionalPutError
// for failed preconditions, idempotent RemoveObject — for every backend. It is
// written to run against any Backend; today it exercises the filesystem
// backend, and any new backend (or S3 fake) should be added to the table so
// the same guarantees the store and trainer rely on are verified uniformly.
func TestBackendContract(t *testing.T) {
	backends := map[string]func(t *testing.T) Backend{
		"filesystem": func(t *testing.T) Backend {
			b, err := NewFilesystemBackend(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			return b
		},
	}

	for name, newBackend := range backends {
		t.Run(name, func(t *testing.T) {
			t.Run("GetObject missing key is os.ErrNotExist", func(t *testing.T) {
				b := newBackend(t)
				_, err := b.GetObject(context.Background(), "filter/nope")
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("GetObject(missing) err = %v; want os.ErrNotExist", err)
				}
			})

			t.Run("StatObject missing key is os.ErrNotExist", func(t *testing.T) {
				b := newBackend(t)
				_, err := b.StatObject(context.Background(), "filter/nope")
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("StatObject(missing) err = %v; want os.ErrNotExist", err)
				}
			})

			t.Run("IfNoneMatch create-once conflicts with ConditionalPutError", func(t *testing.T) {
				b := newBackend(t)
				put := func() error {
					return b.PutObject(context.Background(), "filter/k", bytes.NewReader([]byte("v")), 1,
						PutOptions{IfNoneMatch: "*"})
				}
				if err := put(); err != nil {
					t.Fatalf("first create-once put: %v", err)
				}
				err := put()
				var cond *ConditionalPutError
				if !errors.As(err, &cond) {
					t.Errorf("second create-once put err = %v; want *ConditionalPutError", err)
				}
			})

			t.Run("IfMatch on missing key is ConditionalPutError", func(t *testing.T) {
				b := newBackend(t)
				err := b.PutObject(context.Background(), "filter/missing", bytes.NewReader([]byte("v")), 1,
					PutOptions{IfMatch: "some-etag"})
				var cond *ConditionalPutError
				if !errors.As(err, &cond) {
					t.Errorf("IfMatch on missing key err = %v; want *ConditionalPutError", err)
				}
			})

			t.Run("IfMatch stale ETag is ConditionalPutError; fresh ETag succeeds", func(t *testing.T) {
				b := newBackend(t)
				ctx := context.Background()
				if err := b.PutObject(ctx, "filter/cas", bytes.NewReader([]byte("v1")), 2, PutOptions{}); err != nil {
					t.Fatalf("seed put: %v", err)
				}
				info, err := b.StatObject(ctx, "filter/cas")
				if err != nil {
					t.Fatalf("stat: %v", err)
				}

				// Stale ETag must fail.
				err = b.PutObject(ctx, "filter/cas", bytes.NewReader([]byte("v2")), 2, PutOptions{IfMatch: "stale"})
				var cond *ConditionalPutError
				if !errors.As(err, &cond) {
					t.Errorf("IfMatch stale err = %v; want *ConditionalPutError", err)
				}

				// Current ETag must succeed.
				if err := b.PutObject(ctx, "filter/cas", bytes.NewReader([]byte("v3")), 2, PutOptions{IfMatch: info.ETag}); err != nil {
					t.Errorf("IfMatch fresh err = %v; want success", err)
				}
			})

			t.Run("RemoveObject is idempotent", func(t *testing.T) {
				b := newBackend(t)
				if err := b.RemoveObject(context.Background(), "filter/never-existed"); err != nil {
					t.Errorf("RemoveObject(missing) = %v; want nil (idempotent)", err)
				}
			})

			t.Run("round-trip get returns stored bytes", func(t *testing.T) {
				b := newBackend(t)
				ctx := context.Background()
				if err := b.PutObject(ctx, "filter/rt", bytes.NewReader([]byte("hello")), 5, PutOptions{}); err != nil {
					t.Fatalf("put: %v", err)
				}
				rc, err := b.GetObject(ctx, "filter/rt")
				if err != nil {
					t.Fatalf("get: %v", err)
				}
				defer rc.Close()
				got, _ := io.ReadAll(rc)
				if string(got) != "hello" {
					t.Errorf("round-trip = %q; want %q", got, "hello")
				}
			})
		})
	}
}
