package storage

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// newStubS3 returns an S3Backend talking to a stub HTTP server driven by
// handler. The client uses path-style addressing and a single attempt so the
// stub sees exactly one deterministic request per operation.
func newStubS3(t *testing.T, handler http.HandlerFunc) *S3Backend {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := s3.New(s3.Options{
		BaseEndpoint:     aws.String(srv.URL),
		UsePathStyle:     true,
		Region:           "us-east-1",
		Credentials:      aws.AnonymousCredentials{},
		RetryMaxAttempts: 1,
	})
	return NewS3Backend(client, "test-bucket", nil)
}

// errorXML renders an S3 error response body for the given code.
func errorXML(code string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>` + code +
		`</Code><Message>stub</Message><RequestId>0</RequestId></Error>`
}

// TestS3StatObjectMissingKeyMapsNotExist is the regression test for the S3
// bootstrap deadlock: HeadObject 404s carry NO error body, so the SDK maps
// them to *types.NotFound (never NoSuchKey) — StatObject must still translate
// that to os.ErrNotExist, which train.warmStart (fresh CURRENT) and
// model.Store.Refresh (reset detection) branch on.
func TestS3StatObjectMissingKeyMapsNotExist(t *testing.T) {
	backend := newStubS3(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("unexpected method %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound) // HEAD: status only, no body
	})

	_, err := backend.StatObject(context.Background(), "filter/models/CURRENT")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("StatObject on missing key = %v; want errors.Is(err, os.ErrNotExist)", err)
	}
}

// TestS3BucketExistsMissingBucket pins the same HeadBucket mapping: a 404
// means "bucket absent" (false, nil) so boot can attempt MakeBucket, not a
// storage error that reads as "S3 unreachable".
func TestS3BucketExistsMissingBucket(t *testing.T) {
	backend := newStubS3(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	exists, err := backend.BucketExists(context.Background())
	if err != nil {
		t.Fatalf("BucketExists on missing bucket = %v; want (false, nil)", err)
	}
	if exists {
		t.Fatal("BucketExists = true for a 404 response; want false")
	}
}

// TestS3PutObjectConditionalFailureMapping pins which S3 errors count as a
// benign CAS failure (*ConditionalPutError) versus a real storage error. Real
// S3 answers an If-Match put against a deleted key with 404 and racing
// conditional writers with 409 ConditionalRequestConflict — both must map
// like the filesystem backend's putIfMatch so the trainer's publish aborts
// benignly instead of recording an error run.
func TestS3PutObjectConditionalFailureMapping(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		code     string
		opts     PutOptions
		wantCond bool
	}{
		{"PreconditionFailed with IfMatch", http.StatusPreconditionFailed, "PreconditionFailed",
			PutOptions{IfMatch: `"etag"`}, true},
		{"PreconditionFailed with IfNoneMatch", http.StatusPreconditionFailed, "PreconditionFailed",
			PutOptions{IfNoneMatch: "*"}, true},
		{"ConditionalRequestConflict with IfMatch", http.StatusConflict, "ConditionalRequestConflict",
			PutOptions{IfMatch: `"etag"`}, true},
		{"ConditionalRequestConflict with IfNoneMatch", http.StatusConflict, "ConditionalRequestConflict",
			PutOptions{IfNoneMatch: "*"}, true},
		{"NoSuchKey with IfMatch is a CAS failure", http.StatusNotFound, "NoSuchKey",
			PutOptions{IfMatch: `"etag"`}, true},
		{"NoSuchKey without precondition is a real error", http.StatusNotFound, "NoSuchKey",
			PutOptions{}, false},
		{"unrelated error stays a real error", http.StatusForbidden, "AccessDenied",
			PutOptions{IfMatch: `"etag"`}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newStubS3(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(tt.status)
				fmt.Fprint(w, errorXML(tt.code))
			})

			err := backend.PutObject(context.Background(), "filter/models/CURRENT",
				strings.NewReader("{}"), 2, tt.opts)
			if err == nil {
				t.Fatal("PutObject = nil error; want a failure from the stub")
			}
			var condErr *ConditionalPutError
			if got := errors.As(err, &condErr); got != tt.wantCond {
				t.Fatalf("errors.As(err, *ConditionalPutError) = %v; want %v (err: %v)", got, tt.wantCond, err)
			}
		})
	}
}
