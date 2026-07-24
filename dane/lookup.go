package dane

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// PublishedTLSA is one TLSA resource record as found in DNS.
type PublishedTLSA struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	// Cert is the certificate-association data in lowercase hex.
	Cert string
}

// LookupResult is a definitive answer to a TLSA query: the published record set
// (possibly empty) plus whether the resolver vouched for it with the AD bit.
type LookupResult struct {
	RRs []PublishedTLSA
	// Authenticated reports the resolver's AD bit. Without DNSSEC validation the
	// records exist but DANE clients will not act on them.
	Authenticated bool
}

// Empty reports whether no TLSA records are published.
func (r LookupResult) Empty() bool { return len(r.RRs) == 0 }

// HasDANEEE reports whether any usage-3 (DANE-EE) record is published — the only
// usage whose validity depends on the server's own key.
func (r LookupResult) HasDANEEE() bool {
	for _, rr := range r.RRs {
		if rr.Usage == UsageDANEEE {
			return true
		}
	}
	return false
}

// ContainsSPKIDigest reports whether a "3 1 1 <digest>" record is published.
func (r LookupResult) ContainsSPKIDigest(digest string) bool {
	digest = strings.ToLower(digest)
	for _, rr := range r.RRs {
		if rr.Usage == UsageDANEEE && rr.Selector == SelectorSPKI && rr.MatchingType == MatchingSHA256 && rr.Cert == digest {
			return true
		}
	}
	return false
}

// TLSALookup resolves the TLSA records published for an MX host's SMTP service
// (owner name "_25._tcp.<host>."). A nil error means the answer is definitive —
// NOERROR or NXDOMAIN, with RRs possibly empty. Indeterminate outcomes
// (SERVFAIL, including DNSSEC-bogus zones, timeouts, unreachable resolvers)
// return an error so callers can fail open or closed as their context demands.
type TLSALookup func(ctx context.Context, mxHost string) (LookupResult, error)

// NewResolverLookup returns a TLSALookup querying the given resolvers ("ip" or
// "ip:port") in order until one answers definitively. With no resolvers
// configured it uses the system's /etc/resolv.conf. Queries set the EDNS0 DO
// bit so validating resolvers return the AD flag.
func NewResolverLookup(resolvers []string, timeout time.Duration) TLSALookup {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return func(ctx context.Context, mxHost string) (LookupResult, error) {
		servers, err := resolverAddrs(resolvers)
		if err != nil {
			return LookupResult{}, err
		}

		msg := new(dns.Msg)
		msg.SetQuestion(OwnerName(mxHost), dns.TypeTLSA)
		msg.SetEdns0(4096, true) // DO bit: ask for DNSSEC so AD is meaningful
		msg.RecursionDesired = true

		var lastErr error
		for _, server := range servers {
			resp, err := exchange(ctx, msg, server, timeout)
			if err != nil {
				lastErr = err
				continue
			}
			switch resp.Rcode {
			case dns.RcodeSuccess, dns.RcodeNameError:
				result := LookupResult{Authenticated: resp.AuthenticatedData}
				for _, rr := range resp.Answer {
					if tlsa, ok := rr.(*dns.TLSA); ok {
						result.RRs = append(result.RRs, PublishedTLSA{
							Usage:        tlsa.Usage,
							Selector:     tlsa.Selector,
							MatchingType: tlsa.MatchingType,
							Cert:         strings.ToLower(tlsa.Certificate),
						})
					}
				}
				return result, nil
			default:
				// SERVFAIL and friends are indeterminate — a validating resolver
				// answers SERVFAIL for a DNSSEC-bogus zone, so this must never be
				// treated as "no records".
				lastErr = fmt.Errorf("resolver %s returned %s for %s", server, dns.RcodeToString[resp.Rcode], OwnerName(mxHost))
			}
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no DNS resolvers available")
		}
		return LookupResult{}, fmt.Errorf("tlsa lookup for %s failed: %w", mxHost, lastErr)
	}
}

// exchange queries one server over UDP, retrying over TCP on truncation.
func exchange(ctx context.Context, msg *dns.Msg, server string, timeout time.Duration) (*dns.Msg, error) {
	client := &dns.Client{Timeout: timeout}
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		client.Net = "tcp"
		resp, _, err = client.ExchangeContext(ctx, msg, server)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// resolverAddrs normalizes configured resolvers to "host:port", falling back to
// /etc/resolv.conf when none are configured.
func resolverAddrs(resolvers []string) ([]string, error) {
	if len(resolvers) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("no resolvers configured and reading /etc/resolv.conf failed: %w", err)
		}
		addrs := make([]string, 0, len(conf.Servers))
		for _, s := range conf.Servers {
			addrs = append(addrs, net.JoinHostPort(s, conf.Port))
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no resolvers configured and /etc/resolv.conf lists none")
		}
		return addrs, nil
	}
	addrs := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(r, "53")
		}
		addrs = append(addrs, r)
	}
	return addrs, nil
}
