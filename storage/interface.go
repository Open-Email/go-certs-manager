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

// Backend defines the interface for object storage operations
// This abstraction allows for multiple storage backends (S3, local filesystem, etc.)
type Backend interface {
	// PutObject uploads an object to storage
	PutObject(ctx context.Context, key string, reader io.Reader, size int64, opts PutOptions) error

	// GetObject retrieves an object from storage
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)

	// StatObject returns metadata about an object
	StatObject(ctx context.Context, key string) (ObjectInfo, error)

	// RemoveObject deletes an object from storage
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
}

// ConditionalPutError is returned when a conditional put fails
type ConditionalPutError struct {
	Key string
}

func (e *ConditionalPutError) Error() string {
	return "conditional put failed for key: " + e.Key
}
