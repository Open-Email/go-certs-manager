package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	certmanager "github.com/Open-Email/go-certs-manager"
)

func post(t *testing.T, domain string, renewed []string, err error) (int, []byte) {
	t.Helper()
	w := httptest.NewRecorder()
	WriteRenewResult(w, domain, renewed, err)
	return w.Code, w.Body.Bytes()
}

// The one distinction the whole contract exists for: a spent order must not
// reach a client as the failure it would then retry.
func TestRenewResult_SeparatesASpentOrderFromAFailure(t *testing.T) {
	spent := fmt.Errorf("%w for mx.example.com: storage unavailable", certmanager.ErrOrderNotPersisted)

	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
		wantExit   int
	}{
		{"ordered and stored", nil, http.StatusOK, StatusSuccess, ExitOK},
		{"ordered not stored", spent, http.StatusAccepted, StatusStored, ExitStored},
		{"nothing ordered", errors.New("must run on the cluster leader"), http.StatusInternalServerError, StatusError, ExitFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := post(t, "mx.example.com", []string{"mx.example.com"}, tc.err)
			if code != tc.wantStatus {
				t.Errorf("HTTP %d, want %d", code, tc.wantStatus)
			}
			var got Result
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("response is not JSON: %v (%s)", err, body)
			}
			if got.Status != tc.wantBody {
				t.Errorf("status = %q, want %q", got.Status, tc.wantBody)
			}
			if _, exit := RenewOutcome(code, body); exit != tc.wantExit {
				t.Errorf("exit = %d, want %d", exit, tc.wantExit)
			}
		})
	}
}

// Three codes, all distinct: automation tells "retry" from "never retry" by the
// number alone, so collapsing any two reintroduces the hazard.
func TestRenewOutcome_CodesStayDistinct(t *testing.T) {
	seen := map[int]string{}
	for _, status := range []string{StatusSuccess, StatusStored, StatusError} {
		body, err := json.Marshal(Result{Status: status})
		if err != nil {
			t.Fatal(err)
		}
		_, exit := RenewOutcome(http.StatusOK, body)
		if other, clash := seen[exit]; clash {
			t.Errorf("%q and %q both exit %d", status, other, exit)
		}
		seen[exit] = status
	}
	if len(seen) != 3 {
		t.Errorf("got %d distinct exit codes, want 3", len(seen))
	}
}

// A spent order must say so loudly enough that nobody re-runs it.
func TestRenewOutcome_StoredTellsTheOperatorNotToRetry(t *testing.T) {
	spent := fmt.Errorf("%w: storage unavailable", certmanager.ErrOrderNotPersisted)
	code, body := post(t, "mx.example.com", nil, spent)

	lines, exit := RenewOutcome(code, body)
	out := strings.Join(lines, "\n")
	if exit != ExitStored {
		t.Fatalf("exit = %d, want %d", exit, ExitStored)
	}
	if !strings.Contains(out, "DO NOT re-run") {
		t.Errorf("output does not warn against re-running:\n%s", out)
	}
	if !strings.Contains(out, "mx.example.com") {
		t.Errorf("output does not name the domain:\n%s", out)
	}
}

// A failure the service could not classify must not be advertised as retryable:
// a chain the CA signed that will not build still arrives here.
func TestRenewOutcome_UnclassifiedFailureDoesNotInviteARetry(t *testing.T) {
	code, body := post(t, "mx.example.com", nil, errors.New("persist chain: storage unavailable"))
	lines, exit := RenewOutcome(code, body)
	out := strings.Join(lines, "\n")
	if exit != ExitFailed {
		t.Fatalf("exit = %d, want %d", exit, ExitFailed)
	}
	if strings.Contains(out, "safe to retry") {
		t.Errorf("calls an unclassified failure safe to retry:\n%s", out)
	}
	if !strings.Contains(out, "already spent") {
		t.Errorf("does not warn the order may be spent:\n%s", out)
	}
}

func TestRenewOutcome_HandlesAMissingEndpointAndAnUnreadableBody(t *testing.T) {
	lines, exit := RenewOutcome(http.StatusNotImplemented, []byte(`{"status":"error"}`))
	if exit != ExitFailed || !strings.Contains(strings.Join(lines, "\n"), "endpoint not available") {
		t.Errorf("missing endpoint: exit %d, %v", exit, lines)
	}
	lines, exit = RenewOutcome(http.StatusBadGateway, []byte(`<html>proxy error</html>`))
	if exit != ExitFailed || !strings.Contains(strings.Join(lines, "\n"), "Unreadable response") {
		t.Errorf("unreadable body: exit %d, %v", exit, lines)
	}
}

// The warning has to come before the order, not after it.
func TestRenewPreamble_NamesTheCostBeforeTheCall(t *testing.T) {
	out := strings.Join(RenewPreamble("mx.example.com"), "\n")
	if !strings.Contains(out, "mx.example.com") || !strings.Contains(out, "NEW order") {
		t.Errorf("preamble does not say what the call costs:\n%s", out)
	}
}

type stubRenewer struct {
	err   error
	delay time.Duration
	calls int
}

func (s *stubRenewer) RenewCertificate(domain string) ([]string, error) {
	s.calls++
	time.Sleep(s.delay)
	if s.err != nil {
		return nil, s.err
	}
	return []string{domain}, nil
}

// The whole handler has to outlive the service's ordinary write timeout. This
// runs it behind a real server whose WriteTimeout is far shorter than the
// renewal, the configuration every service ships with.
func TestRenewHandler_OutlastsTheServersWriteTimeout(t *testing.T) {
	renewer := &stubRenewer{delay: 1500 * time.Millisecond}
	srv := httptest.NewUnstartedServer(RenewHandler(func() Renewer { return renewer }, nil))
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"?domain=mx.example.com", "application/json", nil)
	if err != nil {
		t.Fatalf("no answer: %v — the service's WriteTimeout cut the renewal off", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d (%s)", resp.StatusCode, body)
	}
	if _, exit := RenewOutcome(resp.StatusCode, body); exit != ExitOK {
		t.Fatalf("exit = %d, want %d", exit, ExitOK)
	}
}

// Mounted before the manager exists — how smtp-out wires it — the endpoint
// answers "not configured" rather than 404, and starts working once it does.
func TestRenewHandler_LateBoundManager(t *testing.T) {
	var mgr Renewer
	h := RenewHandler(func() Renewer { return mgr }, nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/?domain=mx.example.com", nil))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("HTTP %d before the manager exists, want 501", w.Code)
	}
	if _, exit := RenewOutcome(w.Code, w.Body.Bytes()); exit != ExitFailed {
		t.Fatalf("exit = %d, want %d", exit, ExitFailed)
	}

	mgr = &stubRenewer{}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/?domain=mx.example.com", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d once the manager exists, want 200", w.Code)
	}
}

// Query string and JSON body both carry the domain; neither is an error, and
// only POST is accepted — a GET that ordered a certificate would be a crawler's
// way to spend the weekly allowance.
func TestRenewHandler_RequestShape(t *testing.T) {
	r := &stubRenewer{}
	h := RenewHandler(func() Renewer { return r }, nil)

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/?domain=mx.example.com", nil),
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"domain":"mx.example.com"}`)),
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("HTTP %d for %s %s", w.Code, req.Method, req.URL)
		}
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("HTTP %d with no domain, want 400", w.Code)
	}

	before := r.calls
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/?domain=mx.example.com", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("HTTP %d for GET, want 405", w.Code)
	}
	if r.calls != before {
		t.Error("a GET placed an order")
	}
}

// A request that was sent and got no answer is not a retryable failure: the
// order may be running. This one really is sent — the server accepts it and
// never answers inside the client's deadline.
func TestRenewTransportFailure_SentButUnansweredIsNeverRetryable(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	client := &http.Client{Timeout: 200 * time.Millisecond}
	_, err := client.Post(srv.URL+"?domain=mx.example.com", "application/json", nil)
	if err == nil {
		t.Fatal("setup: expected the client to time out")
	}

	lines, exit := RenewTransportFailure(err)
	if exit != ExitStored {
		t.Fatalf("exit = %d, want %d — a request that may have ordered must not look retryable", exit, ExitStored)
	}
	out := strings.Join(lines, "\n")
	if !strings.Contains(out, "DO NOT re-run") || !strings.Contains(out, "unknown") {
		t.Errorf("does not say the outcome is unknown and forbid re-running:\n%s", out)
	}
}

// A connection that was never made ordered nothing. Warning the operator off a
// retry here would be wrong, and would wear down the warning that matters.
func TestRenewTransportFailure_RefusedConnectionIsSafeToRetry(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens here now

	_, err = http.Post("http://"+addr+"/?domain=mx.example.com", "application/json", nil)
	if err == nil {
		t.Fatal("setup: expected the connection to be refused")
	}

	lines, exit := RenewTransportFailure(err)
	if exit != ExitFailed {
		t.Fatalf("exit = %d, want %d — nothing was sent, so retrying is right", exit, ExitFailed)
	}
	if out := strings.Join(lines, "\n"); !strings.Contains(out, "nothing was ordered") {
		t.Errorf("does not say nothing was ordered:\n%s", out)
	}
}

// The client must be told to wait at least as long as the server will.
func TestRenewTimeout_CoversTwoIssuanceWindows(t *testing.T) {
	if RenewTimeout <= 2*certmanager.IssueTimeout {
		t.Errorf("RenewTimeout %v does not cover a renewal queued behind another issuance (2 × %v)", RenewTimeout, certmanager.IssueTimeout)
	}
}

// End to end through the shared handler: every outcome reaches the operator
// with its exit code, the preamble comes first, and the credentials the CLI
// supplies are what the service sees.
func TestRenew_EndToEnd(t *testing.T) {
	spent := fmt.Errorf("%w: storage unavailable", certmanager.ErrOrderNotPersisted)

	for _, tc := range []struct {
		name     string
		err      error
		wantExit int
		wantLine string
	}{
		{"stored", nil, ExitOK, "ordered and stored"},
		{"spent", spent, ExitStored, "DO NOT re-run"},
		{"failed", errors.New("not the leader"), ExitFailed, "renewal failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			renewer := &stubRenewer{err: tc.err}
			var sawAuth string
			h := RenewHandler(func() Renewer { return renewer }, nil)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawAuth = r.Header.Get("Authorization")
				h.ServeHTTP(w, r)
			}))
			defer srv.Close()

			var out strings.Builder
			exit := Renew(&out, srv.URL, "mx.example.com", func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer secret")
			})

			if exit != tc.wantExit {
				t.Errorf("exit = %d, want %d\n%s", exit, tc.wantExit, out.String())
			}
			if !strings.Contains(out.String(), tc.wantLine) {
				t.Errorf("output does not mention %q:\n%s", tc.wantLine, out.String())
			}
			if !strings.HasPrefix(out.String(), "Renewing mx.example.com") {
				t.Errorf("the preamble is not first:\n%s", out.String())
			}
			if sawAuth != "Bearer secret" {
				t.Errorf("service saw Authorization %q; the CLI's credentials were not applied", sawAuth)
			}
		})
	}
}

// A slow renewal still reaches the CLI through a service whose own
// WriteTimeout is far shorter.
func TestRenew_SlowServiceStillAnswers(t *testing.T) {
	renewer := &stubRenewer{delay: 1500 * time.Millisecond}
	srv := httptest.NewUnstartedServer(RenewHandler(func() Renewer { return renewer }, nil))
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	defer srv.Close()

	var out strings.Builder
	if exit := Renew(&out, srv.URL, "mx.example.com", nil); exit != ExitOK {
		t.Fatalf("exit = %d, want %d:\n%s", exit, ExitOK, out.String())
	}
}

// The bug that shipped was a ten-second client on a two-minute order. Asserted
// directly, because no test that finishes in reasonable time can wait it out.
func TestRenewClient_WaitsForAWholeRenewal(t *testing.T) {
	if got := renewClient().Timeout; got < RenewTimeout {
		t.Fatalf("client gives up after %v; a renewal can take %v", got, RenewTimeout)
	}
}

// A service that is down ordered nothing: exit 1, and say so.
func TestRenew_ServiceDownIsSafeToRetry(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	var out strings.Builder
	if exit := Renew(&out, "http://"+addr, "mx.example.com", nil); exit != ExitFailed {
		t.Fatalf("exit = %d, want %d:\n%s", exit, ExitFailed, out.String())
	}
	if !strings.Contains(out.String(), "nothing was ordered") {
		t.Errorf("does not say nothing was ordered:\n%s", out.String())
	}
}

// lockedBuffer lets the server goroutine read what the CLI has written so far.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The preamble has to be on screen BEFORE the order is placed — printed after,
// it tells the operator what they already spent. Checked from inside the
// service, at the moment the request arrives: output order alone cannot tell
// "before the request" from "after the request, before the result".
func TestRenew_WarnsBeforeTheRequestReachesTheService(t *testing.T) {
	out := &lockedBuffer{}
	var atArrival string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atArrival = out.String()
		WriteRenewResult(w, "mx.example.com", []string{"mx.example.com"}, nil)
	}))
	defer srv.Close()

	Renew(out, srv.URL, "mx.example.com", nil)

	if !strings.Contains(atArrival, "NEW order") {
		t.Fatalf("when the request reached the service the operator had seen only %q; the warning came too late", atArrival)
	}
}

// A status line that arrives without its body is not a failure: the service
// may well have placed the order and been cut off saying so.
func TestRenew_AnAnswerCutOffMidBodyIsOutcomeUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"status\":")
		buf.Flush()
		conn.Close()
	}))
	defer srv.Close()

	var out strings.Builder
	if exit := Renew(&out, srv.URL, "mx.example.com", nil); exit != ExitStored {
		t.Fatalf("exit = %d, want %d — the order may have gone through:\n%s", exit, ExitStored, out.String())
	}
}
