// Provenance: originally smtp-in pkg/storage, hardened in openemail/filter
// (IfMatch CAS, os.ErrNotExist 404 contract, contract test) and upstreamed here.

package storage

import (
	"context"
	"io"
	"time"
)

// ObjectInfo contains metadata about a stored object
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
	ETag         string
}

// Backend defines the interface for object storage operations. This
// abstraction allows for multiple storage backends (S3, local filesystem,
// etc.).
//
// Error contract (load-bearing — the model store, trainer warm start and
// training lease all branch on these, so every implementation MUST honor them;
// TestBackendContract pins them for any backend):
//
//   - GetObject and StatObject MUST return an error satisfying
//     errors.Is(err, os.ErrNotExist) for a missing key — NOT a wrapped SDK
//     error. (This is exactly the smtp-in StatObject-404 bug: S3 HEAD on a
//     missing key returns *types.NotFound, not NoSuchKey, and both must map to
//     os.ErrNotExist.)
//   - PutObject MUST return an error satisfying
//     errors.As(err, **ConditionalPutError) when a precondition fails: an
//     IfNoneMatch:"*" against an existing key, or an IfMatch against a missing
//     key or an ETag mismatch. Any other error is a real failure.
//   - RemoveObject MUST be idempotent: removing a missing key returns nil.
type Backend interface {
	// PutObject uploads an object to storage. A failed IfNoneMatch/IfMatch
	// precondition returns *ConditionalPutError (see the interface doc).
	PutObject(ctx context.Context, key string, reader io.Reader, size int64, opts PutOptions) error

	// GetObject retrieves an object from storage. A missing key returns an
	// error satisfying errors.Is(err, os.ErrNotExist).
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)

	// StatObject returns metadata about an object. A missing key returns an
	// error satisfying errors.Is(err, os.ErrNotExist).
	StatObject(ctx context.Context, key string) (ObjectInfo, error)

	// RemoveObject deletes an object from storage. Idempotent: removing a
	// missing key returns nil.
	RemoveObject(ctx context.Context, key string) error

	// ListObjects lists objects with a given prefix
	ListObjects(ctx context.Context, prefix string, recursive bool) ([]ObjectInfo, error)

	// BucketExists checks if the storage container/bucket exists
	BucketExists(ctx context.Context) (bool, error)

	// MakeBucket creates the storage container/bucket if it doesn't exist
	MakeBucket(ctx context.Context) error
}

// PutOptions contains options for PutObject operation
type PutOptions struct {
	ContentType     string
	ContentEncoding string
	Metadata        map[string]string
	// IfNoneMatch is used for conditional puts (e.g., "*" means only create if not exists)
	IfNoneMatch string
	// IfMatch is used for conditional puts: when non-empty the put succeeds
	// only if the object currently exists with exactly this ETag, otherwise
	// it fails with *ConditionalPutError. Divergence from the openemail/smtp-in
	// original (which only carries IfNoneMatch): this repo adds IfMatch for
	// the trainer's compare-and-swap on the CURRENT model pointer (SPEC2 §3).
	IfMatch string
}

// ConditionalPutError is returned when a conditional put fails
type ConditionalPutError struct {
	Key string
}

func (e *ConditionalPutError) Error() string {
	return "conditional put failed for key: " + e.Key
}
