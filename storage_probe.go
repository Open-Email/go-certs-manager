package certmanager

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Open-Email/go-certs-manager/storage"
)

// verifyConditionalWrites checks that the backend honours If-None-Match: a
// second create-once of the same key must fail with ConditionalPutError.
// The issuance lease and the key create-once are built on it, and a backend
// that silently ignores the condition — some S3-compatible gateways do — lets
// every acquire succeed, so two nodes order for the same domain and two nodes
// can mint different keys for one name. Nothing checked.
//
// Returns (supported, nil) when the probe ran, or an error when it could
// not — storage down at startup — which proves nothing either way.
func verifyConditionalWrites(ctx context.Context, backend storage.Backend, prefix string) (bool, error) {
	key := prefix + "locks/.probe-" + randNodeID()
	create := func() error {
		return backend.PutObject(ctx, key, strings.NewReader("probe"), 5, storage.PutOptions{IfNoneMatch: "*"})
	}
	defer func() { _ = backend.RemoveObject(ctx, key) }()

	if err := create(); err != nil {
		return false, fmt.Errorf("conditional-write probe: first create of %s: %w", key, err)
	}
	err := create()
	var condErr *storage.ConditionalPutError
	switch {
	case err == nil:
		return false, nil
	case errors.As(err, &condErr):
		return true, nil
	default:
		return false, fmt.Errorf("conditional-write probe: second create of %s: %w", key, err)
	}
}
