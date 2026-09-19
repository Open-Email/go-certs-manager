package certstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Open-Email/go-certs-manager/internal/layout"
	"github.com/Open-Email/go-certs-manager/storage"
)

type run struct {
	code     int
	out, err string
	asked    bool
}

// run runs one tls command against the fixture's storage.
func (f *fixture) run(interactive bool, answer string, args ...string) run {
	f.t.Helper()
	return f.runOn(New(f.backend, f.prefix, []string{"mx.example.com"}, 0), interactive, answer, args...)
}

func (f *fixture) runOn(inv *Inventory, interactive bool, answer string, args ...string) run {
	f.t.Helper()
	var out, errOut bytes.Buffer
	asked := false
	env := Env{
		Program: "svc-admin",
		Open:    func(context.Context) (*Inventory, error) { return inv, nil },
		Out:     &out,
		Err:     &errOut,
		Confirm: func(string) bool {
			asked = true
			return answer == "y"
		},
		Interactive: interactive,
	}
	code := Run(env, args)
	return run{code, out.String(), errOut.String(), asked}
}

func TestRun_DeleteRefusesAnInUseCertificateAndSaysHowToReplaceIt(t *testing.T) {
	f := newFixture(t, "")
	f.chain("mx.example.com", fresh)

	r := f.run(true, "y", "delete", "mx.example.com")
	if r.code != ExitFailed {
		t.Fatalf("exit %d, want %d", r.code, ExitFailed)
	}
	if !strings.Contains(r.err, "svc-admin renew-cert mx.example.com") {
		t.Errorf("refusal does not name the command that replaces it:\n%s", r.err)
	}
	if r.asked {
		t.Error("asked for confirmation of something it was going to refuse")
	}
	if !f.stored("mx.example.com") {
		t.Fatal("the certificate is gone")
	}
}

func TestRun_DeleteForceTakesAnInUseCertificateAndSaysItComesBack(t *testing.T) {
	f := newFixture(t, "")
	f.chain("mx.example.com", fresh)

	r := f.run(false, "", "delete", "mx.example.com", "--force", "--yes")
	if r.code != ExitOK {
		t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.err)
	}
	if f.stored("mx.example.com") {
		t.Fatal("still stored")
	}
	if !strings.Contains(r.out, "writes its copy back") {
		t.Errorf("did not say a running leader restores it:\n%s", r.out)
	}
}

// Off a terminal nobody can answer, so waiting would hang a script and
// guessing would delete without consent.
func TestRun_DeleteOffATerminalNeedsYes(t *testing.T) {
	f := newFixture(t, "")
	f.chain("gone.example", fresh)

	r := f.run(false, "y", "delete", "gone.example")
	if r.code != ExitUsage {
		t.Fatalf("exit %d, want %d", r.code, ExitUsage)
	}
	if !f.stored("gone.example") {
		t.Fatal("deleted without confirmation")
	}

	// Flags after the domain count: "delete NAME --yes" is how people type it.
	if r := f.run(false, "", "delete", "gone.example", "--yes"); r.code != ExitOK {
		t.Fatalf("with --yes after the name: exit %d, stderr:\n%s", r.code, r.err)
	}
	if f.stored("gone.example") {
		t.Fatal("--yes after the name was ignored")
	}
}

func TestRun_DeleteAsksAndTakesNoForAnAnswer(t *testing.T) {
	f := newFixture(t, "")
	f.chain("gone.example", fresh)

	if r := f.run(true, "n", "delete", "gone.example"); r.code != ExitOK || !r.asked || !f.stored("gone.example") {
		t.Fatalf("answered no: exit %d, asked %v, stored %v", r.code, r.asked, f.stored("gone.example"))
	}
	if r := f.run(true, "y", "delete", "gone.example"); r.code != ExitOK || f.stored("gone.example") {
		t.Fatalf("answered yes: exit %d, stored %v", r.code, f.stored("gone.example"))
	}
}

func TestAsk_OnlyYesIsYes(t *testing.T) {
	for answer, want := range map[string]bool{"y\n": true, "YES\n": true, " yes \n": true, "n\n": false, "\n": false, "": false, "yep\n": false} {
		var out bytes.Buffer
		if got := Ask(&out, strings.NewReader(answer), "Delete it?"); got != want {
			t.Errorf("answer %q: %v, want %v", answer, got, want)
		}
		if out.String() != "Delete it? [y/N] " {
			t.Errorf("prompt %q", out.String())
		}
	}
}

func TestRun_DeleteNotFoundSuggestsTheNearName(t *testing.T) {
	f := newFixture(t, "")
	f.chain("mx.example.com", fresh)

	r := f.run(false, "", "delete", "mx.exmaple.com", "--yes")
	if r.code != ExitNotFound {
		t.Fatalf("exit %d, want %d", r.code, ExitNotFound)
	}
	if !strings.Contains(r.err, "Did you mean mx.example.com?") {
		t.Errorf("no suggestion:\n%s", r.err)
	}
}

func TestRun_CleanRemovesOnlyWhatCannotBeServed(t *testing.T) {
	f := newFixture(t, "")
	f.chain("mx.example.com", expired)
	f.chain("fine.example", fresh)
	f.put(layout.Chain("", "garbage.example"), []byte("not a certificate"))

	r := f.run(false, "", "clean", "--dry-run")
	if r.code != ExitOK || !f.stored("mx.example.com") || !f.stored("garbage.example") {
		t.Fatalf("dry run: exit %d, and it deleted something", r.code)
	}

	r = f.run(false, "", "clean", "--yes")
	if r.code != ExitOK {
		t.Fatalf("exit %d; stderr:\n%s", r.code, r.err)
	}
	if f.stored("mx.example.com") || f.stored("garbage.example") {
		t.Error("left an unservable certificate")
	}
	if !f.stored("fine.example") {
		t.Error("removed a certificate that can be served")
	}
	if !strings.Contains(r.out, "svc-admin renew-cert mx.example.com") {
		t.Errorf("a configured name was left with nothing, and it did not say what to run:\n%s", r.out)
	}
}

// renewingBackend replaces the expired chain for one name with a fresh one
// right after the first read of it — a renewal landing between clean's listing
// and its delete.
type renewingBackend struct {
	storage.Backend
	key   string
	fresh []byte
	once  sync.Once
}

func (b *renewingBackend) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := b.Backend.GetObject(ctx, key)
	if key == b.key {
		b.once.Do(func() {
			_ = b.Backend.PutObject(ctx, key, bytes.NewReader(b.fresh), int64(len(b.fresh)), storage.PutOptions{})
		})
	}
	return rc, err
}

// Clean decides from a listing; the delete must decide from what is there now.
func TestRun_CleanKeepsAChainRenewedSinceItWasListed(t *testing.T) {
	f := newFixture(t, "")
	f.chain("mx.example.com", expired)
	key, err := f.keys.LoadCertKey(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b := &renewingBackend{Backend: f.backend, key: layout.Chain("", "mx.example.com"), fresh: selfSigned(t, key, "mx.example.com", fresh)}

	r := f.runOn(New(b, "", []string{"mx.example.com"}, 0), false, "", "clean", "--yes")
	if r.code != ExitOK {
		t.Fatalf("exit %d; stderr:\n%s", r.code, r.err)
	}
	if !f.stored("mx.example.com") {
		t.Fatal("deleted a chain renewed after it was listed")
	}
	if !strings.Contains(r.out, "kept mx.example.com") {
		t.Errorf("did not say it kept it:\n%s", r.out)
	}
}

func TestRun_ListFiltersByRoleAndPrintsJSON(t *testing.T) {
	f := newFixture(t, "")
	f.chain("mx.example.com", fresh)
	f.chain("gone.example", fresh)

	r := f.run(false, "", "list", "--role", "orphan", "--json")
	if r.code != ExitOK {
		t.Fatalf("exit %d; stderr:\n%s", r.code, r.err)
	}
	var got []Certificate
	if err := json.Unmarshal([]byte(r.out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, r.out)
	}
	if len(got) != 1 || got[0].Domain != "gone.example" {
		t.Fatalf("got %+v, want only gone.example", got)
	}

	r = f.run(false, "", "list")
	if r.code != ExitOK || !strings.Contains(r.out, "mx.example.com") || !strings.Contains(r.out, "✓ ok") {
		t.Fatalf("table:\n%s", r.out)
	}

	if r := f.run(false, "", "list", "--role", "vanity"); r.code != ExitUsage {
		t.Fatalf("unknown role: exit %d, want %d", r.code, ExitUsage)
	}
}

func TestRun_ListStatusReadsTheRenewalWindow(t *testing.T) {
	window := 30 * 24 * time.Hour
	for _, tc := range []struct {
		left time.Duration
		want string
	}{
		{40 * 24 * time.Hour, "✓ ok"},
		{20 * 24 * time.Hour, "renewing"},
		{10 * 24 * time.Hour, "⚠ overdue"},
	} {
		c := Certificate{Role: RoleConfigured, NotAfter: time.Now().Add(tc.left)}
		if got := status(c, window); got != tc.want {
			t.Errorf("%v left: %q, want %q", tc.left, got, tc.want)
		}
	}
}

// Help must not need a config: it is what someone reads when theirs is wrong.
func TestRun_HelpNeedsNoStorage(t *testing.T) {
	var out bytes.Buffer
	env := Env{
		Program: "svc-admin",
		Open: func(context.Context) (*Inventory, error) {
			t.Fatal("help opened storage")
			return nil, nil
		},
		Out: &out, Err: io.Discard,
	}
	if code := Run(env, []string{"help"}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "svc-admin renew-cert DOMAIN") {
		t.Errorf("help does not use the program's name:\n%s", out.String())
	}
}

func TestRun_ReportsStorageThatWillNotOpen(t *testing.T) {
	var errOut bytes.Buffer
	env := Env{
		Program: "svc-admin",
		Open:    func(context.Context) (*Inventory, error) { return nil, errors.New("no credentials") },
		Out:     io.Discard, Err: &errOut,
	}
	if code := Run(env, []string{"list"}); code != ExitFailed {
		t.Fatalf("exit %d, want %d", code, ExitFailed)
	}
	if !strings.Contains(errOut.String(), "no credentials") {
		t.Errorf("stderr: %s", errOut.String())
	}
}

func TestRun_UnknownCommandSuggests(t *testing.T) {
	var errOut bytes.Buffer
	code := Run(Env{Program: "svc-admin", Out: io.Discard, Err: &errOut}, []string{"lsit"})
	if code != ExitUsage || !strings.Contains(errOut.String(), `did you mean "list"`) {
		t.Fatalf("exit %d:\n%s", code, errOut.String())
	}
}

// The window is the service's, not the default: a fleet renewing 14 days out
// has nothing to renew at 20 days left, where the default would say it does.
func TestRun_ListReadsTheServicesRenewalWindow(t *testing.T) {
	f := newFixture(t, "")
	f.chain("mx.example.com", time.Now().Add(20*24*time.Hour))

	for window, want := range map[time.Duration]string{0: "renewing", 14 * 24 * time.Hour: "✓ ok"} {
		r := f.runOn(New(f.backend, "", []string{"mx.example.com"}, window), false, "", "list")
		if r.code != ExitOK || !strings.Contains(r.out, want) {
			t.Errorf("window %v: want %q in\n%s", window, want, r.out)
		}
	}
}

func TestIsTerminal_DevNullIsNot(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(f) {
		t.Fatal("/dev/null counted as a terminal: a script reading from it would be prompted")
	}
}

// A CLI that prints usage lines itself takes Synopsis and Help; one that does
// not takes Usage. Either way the reader sees each part exactly once.
func TestUsage_IsHelpAroundTheSynopsis(t *testing.T) {
	usage, synopsis, help := Usage("svc-admin"), Synopsis("svc-admin"), Help("svc-admin")
	if strings.Contains(help, "svc-admin tls clean [--dry-run]") {
		t.Error("Help repeats the synopsis")
	}
	for _, line := range strings.Split(strings.TrimSpace(synopsis), "\n") {
		if strings.Count(usage, line) != 1 {
			t.Errorf("Usage has %q %d times, want once", line, strings.Count(usage, line))
		}
	}
	for _, part := range []string{"Flags:", "Exit status:", "svc-admin renew-cert DOMAIN"} {
		if !strings.Contains(help, part) || strings.Count(usage, part) != 1 {
			t.Errorf("%q: in Help %v, in Usage %d times", part, strings.Contains(help, part), strings.Count(usage, part))
		}
	}
}
