package certmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/Open-Email/go-certs-manager/storage"
)

// orderJournal remembers the ACME order in flight for a domain, so that an
// attempt interrupted after the CA has issued — a deploy restart, a context
// deadline, a dropped connection on the download — can collect the
// certificate next time instead of placing another order. The CA counted the
// order the moment it signed; collecting it costs nothing, ordering again
// spends one of the five duplicates a week.
//
// The record is written before anything that can be charged, and removed once
// the certificate is in hand. It is keyed by the certificate key's SPKI, so an
// order placed for the staged key of a replacement ceremony is never mistaken
// for a renewal's.
type orderJournal struct {
	backend storage.Backend
	prefix  string
	logger  *slog.Logger
}

// orderRecord is the object at orders/<domain>.
type orderRecord struct {
	OrderURL  string `json:"order_url"`
	SPKI      string `json:"spki"`       // DANE "3 1 1" digest of the key the order is for
	CreatedAt int64  `json:"created_at"` // unix seconds
}

// orderMaxAge is how long a journaled order is worth resuming. Let's Encrypt
// expires an order seven days after it is created; one that old is not going
// to be collected, and the CA says so anyway.
const orderMaxAge = 7 * 24 * time.Hour

func newOrderJournal(backend storage.Backend, prefix string, logger *slog.Logger) *orderJournal {
	if logger == nil {
		logger = slog.Default()
	}
	return &orderJournal{backend: backend, prefix: prefix, logger: logger}
}

func (j *orderJournal) key(domain string) string {
	return j.prefix + "orders/" + strings.ToLower(domain)
}

// record writes the order in flight for domain.
func (j *orderJournal) record(ctx context.Context, domain, orderURL, spki string) error {
	if j == nil || j.backend == nil {
		return nil
	}
	body, err := json.Marshal(orderRecord{OrderURL: orderURL, SPKI: spki, CreatedAt: time.Now().Unix()})
	if err != nil {
		return err
	}
	return j.backend.PutObject(ctx, j.key(domain), bytes.NewReader(body), int64(len(body)),
		storage.PutOptions{ContentType: "application/json"})
}

// load reads the order in flight for domain. A missing record satisfies
// absentFromStorage; any other error means the journal could not be read,
// which is not the same thing.
func (j *orderJournal) load(ctx context.Context, domain string) (orderRecord, error) {
	var rec orderRecord
	if j == nil || j.backend == nil {
		return rec, fmt.Errorf("no order journal: %w", errNoJournal)
	}
	rc, err := j.backend.GetObject(ctx, j.key(domain))
	if err != nil {
		return rec, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, fmt.Errorf("order journal for %s is unreadable: %w", domain, err)
	}
	return rec, nil
}

// clear forgets the order in flight for domain. Best-effort: a record that
// outlives its order is ignored on the next attempt once the CA reports it
// done, and expires with the order.
func (j *orderJournal) clear(ctx context.Context, domain string) {
	if j == nil || j.backend == nil {
		return
	}
	if err := j.backend.RemoveObject(ctx, j.key(domain)); err != nil {
		j.logger.Debug("TLS: could not clear the order journal", "domain", domain, "error", err)
	}
}
