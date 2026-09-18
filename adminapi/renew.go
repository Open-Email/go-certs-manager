// Package adminapi is the wire contract between a service's certificate-renewal
// endpoint and the admin CLI that drives it.
//
// It lives here, in the library both sides already depend on, because the
// interesting part is a distinction that is easy to lose: a renewal that failed
// and a renewal whose order was paid for but not stored look alike from the
// outside, and only one of them is safe to retry. Every service that can order
// a certificate has to draw it the same way, and a copy per repository drifts —
// the copy that forgets is the one that tells an operator to re-run a command
// that spends another certificate.
package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	certmanager "github.com/Open-Email/go-certs-manager"
)

// Status values carried in a renewal response.
const (
	StatusSuccess = "success" // ordered and stored
	StatusStored  = "stored"  // ordered, NOT stored — the order is spent
	StatusError   = "error"   // nothing was ordered, or the order failed
)

// Exit codes the admin CLI returns. They are an interface with automation: an
// ansible `command` task retries on any non-zero rc, so the one outcome that
// must never be retried needs a code of its own rather than sharing the generic
// failure.
const (
	ExitOK     = 0
	ExitFailed = 1
	ExitStored = 2
)

// Result is the JSON body of a renewal response.
type Result struct {
	Status  string   `json:"status"`
	Message string   `json:"message,omitempty"`
	Error   string   `json:"error,omitempty"`
	Renewed []string `json:"renewed,omitempty"`
}

// WriteRenewResult writes the outcome of a Manager.RenewCertificate call.
//
// An error wrapping certmanager.ErrOrderNotPersisted answers 202, not 500: the
// CA signed the certificate, the node is serving it, and storage has not taken
// it yet. Sending it as a plain failure puts it in the bucket clients call
// retryable, and the retry buys a second certificate for one already in hand.
func WriteRenewResult(w http.ResponseWriter, domain string, renewed []string, err error) {
	w.Header().Set("Content-Type", "application/json")

	switch {
	case err == nil:
		w.WriteHeader(http.StatusOK)
		writeJSON(w, Result{
			Status:  StatusSuccess,
			Message: fmt.Sprintf("Certificate re-issued for %s (persistent key reused — SPKI unchanged)", domain),
			Renewed: renewed,
		})
	case errors.Is(err, certmanager.ErrOrderNotPersisted):
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, Result{
			Status:  StatusStored,
			Error:   err.Error(),
			Renewed: []string{domain},
		})
	default:
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, Result{Status: StatusError, Error: err.Error()})
	}
}

func writeJSON(w http.ResponseWriter, r Result) {
	_ = json.NewEncoder(w).Encode(r)
}

// RenewPreamble is what the CLI prints BEFORE the request. Before, not after:
// the call always places an order, so an operator who ran it to look at
// something has already spent one by the time any result appears.
func RenewPreamble(domain string) []string {
	return []string{
		fmt.Sprintf("Renewing %s — this places a NEW order with Let's Encrypt.", domain),
		"Let's Encrypt allows 5 certificates per name per week.",
	}
}

// RenewOutcome turns a response into what to print and what to exit with.
func RenewOutcome(httpStatus int, body []byte) ([]string, int) {
	if httpStatus == http.StatusNotFound || httpStatus == http.StatusNotImplemented {
		return []string{
			"✗ Certificate renewal endpoint not available",
			"  Ensure the service is running with TLS (letsencrypt) enabled",
		}, ExitFailed
	}

	var result Result
	if err := json.Unmarshal(body, &result); err != nil {
		return []string{
			"✗ Certificate renewal failed",
			fmt.Sprintf("  Unreadable response (HTTP %d): %s", httpStatus, strings.TrimSpace(string(body))),
		}, ExitFailed
	}

	switch result.Status {
	case StatusSuccess:
		lines := []string{"✓ Certificate ordered and stored"}
		if result.Message != "" {
			lines = append(lines, "  "+result.Message)
		}
		for _, d := range result.Renewed {
			lines = append(lines, "  "+d)
		}
		return append(lines, "  It is in service on this node and in shared storage."), ExitOK

	case StatusStored:
		lines := []string{"⚠ Certificate ordered, but NOT written to shared storage"}
		if result.Error != "" {
			lines = append(lines, "  "+result.Error)
		}
		for _, d := range result.Renewed {
			lines = append(lines, "  "+d)
		}
		return append(lines,
			"  This node is serving it and retries the write every few minutes.",
			"  DO NOT re-run this: the order is already spent, and another would",
			"  buy a certificate we hold. Fix storage instead, then check the",
			"  certificate listing.",
		), ExitStored

	default:
		lines := []string{"✗ Certificate renewal failed"}
		if result.Error != "" {
			lines = append(lines, "  "+result.Error)
		} else {
			lines = append(lines, fmt.Sprintf("  HTTP %d", httpStatus))
		}
		// Deliberately not "safe to retry". The common spent-order case is
		// reported as stored, but one still arrives here: a chain the CA signed
		// that will not build — spent, with nothing to serve.
		return append(lines,
			"  Check the certificate listing before re-running: if the failure",
			"  came after the CA signed, the order is already spent.",
		), ExitFailed
	}
}
