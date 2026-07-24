// Provenance: originally smtp-in pkg/storage, hardened in openemail/filter
// (IfMatch CAS, os.ErrNotExist 404 contract, contract test) and upstreamed here.

package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3Backend implements the Backend interface using AWS S3
type S3Backend struct {
	client *s3.Client
	bucket string
	logger *slog.Logger
}

// NewS3Backend creates a new S3 storage backend
func NewS3Backend(client *s3.Client, bucket string, logger *slog.Logger) *S3Backend {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &S3Backend{
		client: client,
		bucket: bucket,
		logger: logger,
	}
}

// PutObject uploads an object to S3
func (s *S3Backend) PutObject(ctx context.Context, key string, reader io.Reader, size int64, opts PutOptions) error {
	input := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   reader,
	}

	if opts.ContentType != "" {
		input.ContentType = aws.String(opts.ContentType)
	}

	if opts.ContentEncoding != "" {
		input.ContentEncoding = aws.String(opts.ContentEncoding)
	}

	if opts.Metadata != nil {
		input.Metadata = opts.Metadata
	}

	// Handle conditional put (IfNoneMatch: "*" means only create if not exists)
	if opts.IfNoneMatch == "*" {
		input.IfNoneMatch = aws.String("*")
	}

	// Handle conditional put (IfMatch: replace only if the ETag still matches).
	if opts.IfMatch != "" {
		input.IfMatch = aws.String(opts.IfMatch)
	}

	_, err := s.client.PutObject(ctx, input)
	if err != nil {
		// Check for conditional put failure
		var ae smithy.APIError
		if errors.As(err, &ae) && isConditionalPutFailure(ae.ErrorCode(), opts) {
			s.logger.Debug("Conditional put failed", "key", key, "code", ae.ErrorCode())
			return &ConditionalPutError{Key: key}
		}
		return fmt.Errorf("failed to put object to S3: %w", err)
	}

	s.logger.Debug("Stored object to S3", "key", key, "size", size)
	return nil
}

// isConditionalPutFailure reports whether an S3 error code means the put's
// PRECONDITION failed rather than the operation itself. PreconditionFailed is
// the canonical If-Match/If-None-Match failure. ConditionalRequestConflict
// (HTTP 409) is returned when concurrent conditional writers race on one key.
// An If-Match put whose target no longer exists fails with a 404 (NoSuchKey /
// NotFound) — exactly the CAS-against-deleted-object case the filesystem
// backend's putIfMatch maps to *ConditionalPutError, so the backends agree;
// the 404 mapping is guarded on IfMatch actually being requested so unrelated
// 404s from unconditional puts still surface as real errors.
func isConditionalPutFailure(code string, opts PutOptions) bool {
	switch code {
	case "PreconditionFailed":
		return true
	case "ConditionalRequestConflict":
		return opts.IfMatch != "" || opts.IfNoneMatch != ""
	case "NoSuchKey", "NotFound":
		return opts.IfMatch != ""
	}
	return false
}

// GetObject retrieves an object from S3
func (s *S3Backend) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			s.logger.Debug("Object not found in S3", "key", key)
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("failed to get object from S3: %w", err)
	}

	s.logger.Debug("Retrieved object from S3", "key", key)
	return result.Body, nil
}

// StatObject returns metadata about an object in S3
func (s *S3Backend) StatObject(ctx context.Context, key string) (ObjectInfo, error) {
	result, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		// HeadObject 404s have no XML error body, so the SDK maps them by
		// status code to *types.NotFound — NoSuchKey is a GetObject-only
		// error and NEVER matches here. Both are checked so exotic
		// S3-compatible gateways that do synthesize NoSuchKey still map.
		// This mapping is load-bearing: warm-start bootstrap and the model
		// store's reset detection both branch on os.ErrNotExist.
		var nsk *types.NoSuchKey
		var nf *types.NotFound
		if errors.As(err, &nsk) || errors.As(err, &nf) {
			return ObjectInfo{}, os.ErrNotExist
		}
		return ObjectInfo{}, fmt.Errorf("failed to stat object in S3: %w", err)
	}

	etag := ""
	if result.ETag != nil {
		etag = *result.ETag
	}

	return ObjectInfo{
		Key:          key,
		Size:         *result.ContentLength,
		LastModified: *result.LastModified,
		ETag:         etag,
	}, nil
}

// RemoveObject deletes an object from S3
func (s *S3Backend) RemoveObject(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			s.logger.Debug("Object already removed from S3", "key", key)
			return nil // Consider already removed as success
		}
		return fmt.Errorf("failed to remove object from S3: %w", err)
	}

	s.logger.Debug("Removed object from S3", "key", key)
	return nil
}

// ListObjects lists objects with a given prefix in S3
func (s *S3Backend) ListObjects(ctx context.Context, prefix string, recursive bool) ([]ObjectInfo, error) {
	var objects []ObjectInfo

	delimiter := "/"
	if recursive {
		delimiter = ""
	}

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	}
	if delimiter != "" {
		input.Delimiter = aws.String(delimiter)
	}

	paginator := s3.NewListObjectsV2Paginator(s.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			s.logger.Error("Error listing objects from S3", "error", err)
			return nil, err
		}

		for _, obj := range page.Contents {
			etag := ""
			if obj.ETag != nil {
				etag = *obj.ETag
			}

			objects = append(objects, ObjectInfo{
				Key:          *obj.Key,
				Size:         *obj.Size,
				LastModified: *obj.LastModified,
				ETag:         etag,
			})
		}
	}

	s.logger.Debug("Listed objects from S3",
		"prefix", prefix,
		"recursive", recursive,
		"count", len(objects))

	return objects, nil
}

// BucketExists checks if the S3 bucket exists
func (s *S3Backend) BucketExists(ctx context.Context) (bool, error) {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(s.bucket),
	})
	if err != nil {
		// Like HeadObject, a HeadBucket 404 deserializes to *types.NotFound
		// (no error body to name NoSuchBucket); both are checked so a
		// missing bucket reports (false, nil) — bucket absent — instead of
		// masquerading as an unreachable endpoint.
		var nsb *types.NoSuchBucket
		var nf *types.NotFound
		if errors.As(err, &nsb) || errors.As(err, &nf) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check S3 bucket: %w", err)
	}
	return true, nil
}

// MakeBucket creates the S3 bucket if it doesn't exist
func (s *S3Backend) MakeBucket(ctx context.Context) error {
	_, err := s.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(s.bucket),
	})
	if err != nil {
		// Check if bucket already exists
		var bae *types.BucketAlreadyExists
		var baoby *types.BucketAlreadyOwnedByYou
		if errors.As(err, &bae) || errors.As(err, &baoby) {
			s.logger.Info("S3 bucket already exists", "bucket", s.bucket)
			return nil
		}
		return fmt.Errorf("failed to create S3 bucket: %w", err)
	}

	s.logger.Info("Created S3 bucket", "bucket", s.bucket)
	return nil
}
