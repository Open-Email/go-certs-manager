package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"log/slog"
)

func TestNewFilesystemBackend(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend, err := NewFilesystemBackend(tmpDir, logger)
	if err != nil {
		t.Fatalf("NewFilesystemBackend failed: %v", err)
	}
	if backend == nil {
		t.Fatal("Backend is nil")
	}

	t.Log("✓ Filesystem backend created successfully")
}

func TestNewFilesystemBackend_NilLogger(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, err := NewFilesystemBackend(tmpDir, nil)
	if err != nil {
		t.Fatalf("NewFilesystemBackend failed: %v", err)
	}
	if backend == nil {
		t.Fatal("Backend is nil")
	}

	t.Log("✓ Filesystem backend works with nil logger")
}

func TestFilesystemBackend_PutGetObject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// Put object
	data := []byte("test data content")
	err = backend.PutObject(ctx, "test/key.txt", bytes.NewReader(data), int64(len(data)), PutOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Get object
	reader, err := backend.GetObject(ctx, "test/key.txt")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	defer reader.Close()

	// Read and verify content
	retrieved, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read object: %v", err)
	}

	if !bytes.Equal(data, retrieved) {
		t.Errorf("Data mismatch: expected %s, got %s", data, retrieved)
	}

	t.Log("✓ Put/Get object works correctly")
}

func TestFilesystemBackend_PutObject_ConditionalPut(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// First put with IfNoneMatch: "*" - should succeed
	data := []byte("test data")
	opts := PutOptions{IfNoneMatch: "*"}
	err = backend.PutObject(ctx, "test/conditional.txt", bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		t.Fatalf("First conditional put should succeed: %v", err)
	}

	// Second put with IfNoneMatch: "*" - should fail
	err = backend.PutObject(ctx, "test/conditional.txt", bytes.NewReader(data), int64(len(data)), opts)
	if err == nil {
		t.Error("Second conditional put should fail")
	}
	if _, ok := err.(*ConditionalPutError); !ok {
		t.Errorf("Expected ConditionalPutError, got %T", err)
	}

	t.Log("✓ Conditional put works correctly")
}

func TestFilesystemBackend_StatObject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// Put object
	data := []byte("test data for stat")
	err = backend.PutObject(ctx, "test/stat.txt", bytes.NewReader(data), int64(len(data)), PutOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Stat object
	info, err := backend.StatObject(ctx, "test/stat.txt")
	if err != nil {
		t.Fatalf("StatObject failed: %v", err)
	}

	if info.Key != "test/stat.txt" {
		t.Errorf("Expected key 'test/stat.txt', got '%s'", info.Key)
	}
	if info.Size != int64(len(data)) {
		t.Errorf("Expected size %d, got %d", len(data), info.Size)
	}
	if info.ETag == "" {
		t.Error("ETag should not be empty")
	}
	if info.LastModified.IsZero() {
		t.Error("LastModified should not be zero")
	}

	t.Log("✓ StatObject works correctly")
}

func TestFilesystemBackend_StatObject_NotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	_, err = backend.StatObject(ctx, "nonexistent/key.txt")
	if err != os.ErrNotExist {
		t.Errorf("Expected os.ErrNotExist, got %v", err)
	}

	t.Log("✓ StatObject returns ErrNotExist for missing file")
}

func TestFilesystemBackend_RemoveObject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// Put object
	data := []byte("test data")
	err = backend.PutObject(ctx, "test/remove.txt", bytes.NewReader(data), int64(len(data)), PutOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Verify it exists
	_, err = backend.StatObject(ctx, "test/remove.txt")
	if err != nil {
		t.Fatal("Object should exist before removal")
	}

	// Remove object
	err = backend.RemoveObject(ctx, "test/remove.txt")
	if err != nil {
		t.Fatalf("RemoveObject failed: %v", err)
	}

	// Verify it's gone
	_, err = backend.StatObject(ctx, "test/remove.txt")
	if err != os.ErrNotExist {
		t.Error("Object should not exist after removal")
	}

	t.Log("✓ RemoveObject works correctly")
}

func TestFilesystemBackend_RemoveObject_NotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// Remove non-existent object should not error
	err = backend.RemoveObject(ctx, "nonexistent/key.txt")
	if err != nil {
		t.Errorf("RemoveObject should succeed for nonexistent file, got: %v", err)
	}

	t.Log("✓ RemoveObject succeeds for nonexistent file")
}

func TestFilesystemBackend_ListObjects_Recursive(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// Create multiple objects
	objects := []string{
		"dir1/file1.txt",
		"dir1/file2.txt",
		"dir1/subdir/file3.txt",
		"dir2/file4.txt",
	}

	for _, key := range objects {
		data := []byte("content for " + key)
		err = backend.PutObject(ctx, key, bytes.NewReader(data), int64(len(data)), PutOptions{})
		if err != nil {
			t.Fatalf("PutObject failed for %s: %v", key, err)
		}
	}

	// List all objects recursively under dir1
	results, err := backend.ListObjects(ctx, "dir1", true)
	if err != nil {
		t.Fatalf("ListObjects failed: %v", err)
	}

	// Should find 3 files (file1, file2, file3)
	if len(results) != 3 {
		t.Errorf("Expected 3 objects, got %d", len(results))
	}

	t.Log("✓ ListObjects recursive works correctly")
}

func TestFilesystemBackend_ListObjects_NonRecursive(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// Create multiple objects
	objects := []string{
		"dir1/file1.txt",
		"dir1/file2.txt",
		"dir1/subdir/file3.txt",
	}

	for _, key := range objects {
		data := []byte("content for " + key)
		err = backend.PutObject(ctx, key, bytes.NewReader(data), int64(len(data)), PutOptions{})
		if err != nil {
			t.Fatalf("PutObject failed for %s: %v", key, err)
		}
	}

	// List objects non-recursively under dir1
	results, err := backend.ListObjects(ctx, "dir1", false)
	if err != nil {
		t.Fatalf("ListObjects failed: %v", err)
	}

	// Should find 2 files (file1, file2) - not file3 in subdir
	if len(results) != 2 {
		t.Errorf("Expected 2 objects, got %d", len(results))
	}

	t.Log("✓ ListObjects non-recursive works correctly")
}

func TestFilesystemBackend_ListObjects_Empty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// List objects in nonexistent directory
	results, err := backend.ListObjects(ctx, "nonexistent", true)
	if err != nil {
		t.Fatalf("ListObjects failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected 0 objects, got %d", len(results))
	}

	t.Log("✓ ListObjects returns empty for nonexistent prefix")
}

func TestFilesystemBackend_BucketExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "storage-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	exists, err := backend.BucketExists(ctx)
	if err != nil {
		t.Fatalf("BucketExists failed: %v", err)
	}
	if !exists {
		t.Error("Bucket should exist")
	}

	t.Log("✓ BucketExists works correctly")
}

func TestFilesystemBackend_BucketExists_NotExists(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "nonexistent-storage-dir")

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	exists, err := backend.BucketExists(ctx)
	if err != nil {
		t.Fatalf("BucketExists failed: %v", err)
	}
	if exists {
		t.Error("Bucket should not exist")
	}

	t.Log("✓ BucketExists returns false for nonexistent directory")
}

func TestFilesystemBackend_MakeBucket(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "storage-test-makebucket")
	defer os.RemoveAll(tmpDir)

	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// Bucket shouldn't exist yet
	exists, _ := backend.BucketExists(ctx)
	if exists {
		t.Error("Bucket should not exist yet")
	}

	// Create bucket
	err := backend.MakeBucket(ctx)
	if err != nil {
		t.Fatalf("MakeBucket failed: %v", err)
	}

	// Bucket should exist now
	exists, _ = backend.BucketExists(ctx)
	if !exists {
		t.Error("Bucket should exist after MakeBucket")
	}

	t.Log("✓ MakeBucket works correctly")
}

func TestFilesystemBackend_GetFullPath(t *testing.T) {
	tmpDir := "/tmp/storage-test"
	backend, _ := NewFilesystemBackend(tmpDir, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Test normal key
	path, ok := backend.getFullPath("test/key.txt")
	expected := filepath.Join(tmpDir, "test/key.txt")
	if !ok || path != expected {
		t.Errorf("Expected %s (ok=true), got %s (ok=%v)", expected, path, ok)
	}

	// Test key with leading slash (should be cleaned)
	path, ok = backend.getFullPath("/test/key.txt")
	if !ok || path != expected {
		t.Errorf("Expected %s (ok=true), got %s (ok=%v)", expected, path, ok)
	}

	// Test key with .. that stays within base (should succeed)
	path, ok = backend.getFullPath("test/../key.txt")
	expected = filepath.Join(tmpDir, "key.txt")
	if !ok || path != expected {
		t.Errorf("Expected %s (ok=true), got %s (ok=%v)", expected, path, ok)
	}

	// Test directory traversal attack (should be blocked)
	_, ok = backend.getFullPath("../../etc/passwd")
	if ok {
		t.Error("Expected path traversal to be blocked, but it was allowed")
	}

	_, ok = backend.getFullPath("../../../etc/shadow")
	if ok {
		t.Error("Expected path traversal to be blocked, but it was allowed")
	}

	t.Log("✓ getFullPath sanitizes keys and blocks traversal correctly")
}

func TestGenerateETag(t *testing.T) {
	// Test that ETag is generated consistently
	key := "test/key.txt"
	modTime := time.Now()

	etag1 := generateETag(key, modTime)
	etag2 := generateETag(key, modTime)

	if etag1 != etag2 {
		t.Error("ETag should be consistent for same inputs")
	}

	if etag1 == "" {
		t.Error("ETag should not be empty")
	}

	if len(etag1) != 32 { // MD5 hex is 32 characters
		t.Errorf("ETag should be 32 characters, got %d", len(etag1))
	}

	t.Log("✓ generateETag works correctly")
}

func TestConditionalPutError(t *testing.T) {
	err := &ConditionalPutError{Key: "test/key.txt"}
	expected := "conditional put failed for key: test/key.txt"

	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}

	t.Log("✓ ConditionalPutError implements error interface")
}
