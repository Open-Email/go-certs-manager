package dane

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// serveDNS runs a local UDP DNS server for the test and returns its address.
func serveDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func tlsaAnswer(q dns.Question, usage, selector, matching uint8, cert string) dns.RR {
	return &dns.TLSA{
		Hdr:          dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage:        usage,
		Selector:     selector,
		MatchingType: matching,
		Certificate:  cert,
	}
}

func TestNewResolverLookup_FindsRecords(t *testing.T) {
	addr := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = true
		q := r.Question[0]
		if q.Name != "_25._tcp.mx.example.com." || q.Qtype != dns.TypeTLSA {
			m.Rcode = dns.RcodeNameError
		} else {
			// Uppercase on the wire — the lookup must normalize to lowercase.
			m.Answer = append(m.Answer, tlsaAnswer(q, 3, 1, 1, strings.ToUpper(testDigest)))
			m.Answer = append(m.Answer, tlsaAnswer(q, 2, 0, 1, strings.Repeat("ab", 32)))
		}
		_ = w.WriteMsg(m)
	})

	lookup := NewResolverLookup([]string{addr}, 2*time.Second)
	got, err := lookup(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RRs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got.RRs))
	}
	if !got.Authenticated {
		t.Fatal("expected AD bit to be reported")
	}
	if !got.ContainsSPKIDigest(strings.ToUpper(testDigest)) {
		t.Fatal("ContainsSPKIDigest must match case-insensitively")
	}
	if got.ContainsSPKIDigest(strings.Repeat("ab", 32)) {
		t.Fatal("a 2 0 1 record must not satisfy ContainsSPKIDigest")
	}
	if !got.HasDANEEE() {
		t.Fatal("expected HasDANEEE")
	}
}

func TestNewResolverLookup_NoData(t *testing.T) {
	addr := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r) // NOERROR, empty answer
		_ = w.WriteMsg(m)
	})
	lookup := NewResolverLookup([]string{addr}, 2*time.Second)
	got, err := lookup(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatalf("NODATA must be definitive, got error: %v", err)
	}
	if !got.Empty() || got.HasDANEEE() {
		t.Fatalf("expected empty result, got %+v", got)
	}
}

func TestNewResolverLookup_NXDomain(t *testing.T) {
	addr := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})
	lookup := NewResolverLookup([]string{addr}, 2*time.Second)
	got, err := lookup(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatalf("NXDOMAIN must be definitive, got error: %v", err)
	}
	if !got.Empty() {
		t.Fatalf("expected empty result, got %+v", got)
	}
}

func TestNewResolverLookup_ServFailIsError(t *testing.T) {
	addr := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	lookup := NewResolverLookup([]string{addr}, 2*time.Second)
	if _, err := lookup(context.Background(), "mx.example.com"); err == nil {
		t.Fatal("SERVFAIL must be indeterminate (error), not an empty result")
	}
}

func TestNewResolverLookup_FailsOverToSecondResolver(t *testing.T) {
	bad := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	good := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, tlsaAnswer(r.Question[0], 3, 1, 1, testDigest))
		_ = w.WriteMsg(m)
	})
	lookup := NewResolverLookup([]string{bad, good}, 2*time.Second)
	got, err := lookup(context.Background(), "mx.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ContainsSPKIDigest(testDigest) {
		t.Fatal("expected digest from the second resolver")
	}
}

func TestNewResolverLookup_UnreachableResolverIsError(t *testing.T) {
	// Reserve a port and close it so nothing answers.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	lookup := NewResolverLookup([]string{addr}, 500*time.Millisecond)
	if _, err := lookup(context.Background(), "mx.example.com"); err == nil {
		t.Fatal("unreachable resolver must yield an error")
	}
}
