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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	certmanager "github.com/Open-Email/go-certs-manager"
)

// Status values carried in a renewal response.
const (
	StatusSuccess = "success" // ordered and stored
	StatusStored  = "stored"  // ordered, NOT stored — the order is spent
	StatusError   = "error"   // nothing was ordered, or the order failed
)

// RenewTimeout is how long both ends of a renewal must be prepared to wait.
//
// A renewal is a whole ACME order run synchronously, and it may first queue
// behind a maintenance issuance holding the same domain — two issuance windows
// back to back, plus margin. The services' default HTTP timeouts are seconds:
// a client that gives up at ten reports a failure while the order carries on,
// and the operator retries into a second one. RenewHandler extends the
// server's write deadline to this, and a CLI must give its client at least as
// long.
//
// Waiting longer still cannot be unsafe, because a request that gets no
// answer is reported as outcome-unknown, not as a failure (see
// RenewTransportFailure). The timeout decides only whether the operator gets a
// definite answer.
const RenewTimeout = 2*certmanager.IssueTimeout + time.Minute

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

// Renewer is what RenewHandler drives — certmanager.Manager satisfies it.
type Renewer interface {
	RenewCertificate(domain string) ([]string, error)
}

// RenewHandler serves a renewal request: POST, with the domain in the query
// string (?domain=) or a JSON body ({"domain": ...}).
//
// renewer is called per request, so a service can mount this before its
// certificate manager exists and have it answer 501 until it does. Every
// service mounting the same handler is the point: the request shape, the
// deadline and the classification cannot drift between them.
func RenewHandler(renewer func() Renewer, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var mgr Renewer
		if renewer != nil {
			mgr = renewer()
		}
		if mgr == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			writeJSON(w, Result{Status: StatusError, Error: "certificate renewal not configured (no Let's Encrypt manager on this node)"})
			return
		}

		domain := r.URL.Query().Get("domain")
		if domain == "" && r.Body != nil {
			var body struct {
				Domain string `json:"domain"`
			}
			_ = json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body)
			domain = body.Domain
		}
		if domain == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, Result{Status: StatusError, Error: "domain parameter is required"})
			return
		}

		// The service's own WriteTimeout is sized for requests that take
		// milliseconds. Left alone it cuts this response off mid-order, and the
		// client learns nothing about an order that went ahead anyway. The
		// renewal itself runs on its own context, so a client that disconnects
		// does not abandon an order the CA is already working on.
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(RenewTimeout)); err != nil {
			logger.Debug("TLS: could not extend the write deadline for a renewal", "error", err)
		}

		logger.Info("Certificate renewal requested", "domain", domain)
		renewed, err := mgr.RenewCertificate(domain)
		if err != nil {
			logger.Error("Certificate renewal failed", "domain", domain, "error", err)
		}
		WriteRenewResult(w, domain, renewed, err)
	})
}

// RenewTransportFailure is the outcome when the request got no answer.
//
// Two different things, told apart by whether the connection was ever made:
//
//   - The dial failed — refused, no such host, unreachable. Nothing was sent,
//     so nothing was ordered, and running it again is exactly right. Calling
//     this "unknown" would teach operators to ignore the warning that matters.
//   - Anything after that — a timeout waiting for the answer, a connection
//     reset mid-response. The request may have arrived and the order may be
//     under way; a client that gave up has no way to know. The only safe
//     instruction is the spent-order one, with its exit code.
func RenewTransportFailure(err error) ([]string, int) {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return []string{
			"✗ Could not reach the service — nothing was ordered",
			"  " + err.Error(),
			"  Check that it is running and the URL is right, then run it again.",
		}, ExitFailed
	}
	return []string{
		"⚠ No answer from the service — the outcome is unknown",
		"  " + err.Error(),
		"  The order may have gone ahead. DO NOT re-run this until the",
		"  certificate listing shows it did not: re-running spends another.",
	}, ExitStored
}

// Renew runs the client side of a renewal against endpoint, writes what the
// operator needs to see to out, and returns the exit code the CLI should use.
//
// A CLI calls this and exits with the result; it owns every part that matters,
// so none can be got wrong in one repository and right in another. The
// preamble is written BEFORE the request, because the request always spends
// an order. The HTTP client waits RenewTimeout, not whatever the CLI uses for
// its quick commands — ten seconds was the bug that shipped. And a request
// with no answer, or an answer cut off mid-body, goes through
// RenewTransportFailure rather than being reported as an ordinary error.
//
// authorize adds the service's credentials to the request; nil for none.
func Renew(out io.Writer, endpoint, domain string, authorize func(*http.Request)) int {
	for _, line := range RenewPreamble(domain) {
		fmt.Fprintln(out, line)
	}

	body, err := json.Marshal(map[string]string{"domain": domain})
	if err != nil {
		fmt.Fprintln(out, "✗ Certificate renewal failed")
		fmt.Fprintln(out, "  "+err.Error())
		return ExitFailed
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(out, "✗ Certificate renewal failed")
		fmt.Fprintln(out, "  "+err.Error())
		return ExitFailed
	}
	req.Header.Set("Content-Type", "application/json")
	if authorize != nil {
		authorize(req)
	}

	var lines []string
	var code int
	resp, err := renewClient().Do(req)
	if err != nil {
		lines, code = RenewTransportFailure(err)
	} else {
		defer resp.Body.Close()
		raw, rerr := io.ReadAll(resp.Body)
		if rerr != nil {
			// The status line arrived and the body did not: the order may well
			// have gone through, so this is the unknown case, not a failure.
			lines, code = RenewTransportFailure(rerr)
		} else {
			lines, code = RenewOutcome(resp.StatusCode, raw)
		}
	}
	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
	return code
}

// renewClient is the HTTP client Renew uses. Separate so its deadline can be
// asserted directly: the bug it exists to prevent — a ten-second client on a
// two-minute order — cannot be caught by a test that waits less than ten
// seconds.
func renewClient() *http.Client {
	return &http.Client{Timeout: RenewTimeout}
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
