package certmanager

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Open-Email/go-certs-manager/dane"
	"github.com/Open-Email/go-certs-manager/internal/safego"
	"github.com/Open-Email/go-certs-manager/storage"

	"golang.org/x/crypto/acme"
)

// Config configures the TLS certificate manager.
type Config struct {
	Enabled     bool
	Provider    string // must be "letsencrypt" — anything else returns (nil, nil)
	LetsEncrypt LetsEncryptConfig

	// DNSResolvers are the resolvers used for read-only DANE TLSA verification
	// ("ip" or "ip:port"); empty = system /etc/resolv.conf. Mirrors the global
	// [dns] config.
	DNSResolvers []string
	// DNSTimeoutSeconds bounds each TLSA verification query (0 = 5s).
	DNSTimeoutSeconds int
	// OnDANEPublishedMatch, when set, receives the per-host DANE drift signal on
	// every maintenance tick: matched is true when the TLSA records published in
	// DNS exactly match the desired set. Wire it to a metrics gauge.
	OnDANEPublishedMatch func(host string, matched bool)

	// OnDemand, when set, adds a DYNAMIC allow-set on top of the static
	// LetsEncrypt.Domains whitelist: hostnames enumerated from an external
	// authority (a multi-tenant control plane) are served and renewed exactly
	// like configured ones, without a config change or a restart.
	//
	// The static list keeps its meaning — those are the platform's own names,
	// always allowed, never dependent on the control plane being reachable. See
	// OnDemandConfig for the rate-limit reasoning that shapes the rest.
	OnDemand *OnDemandConfig
}

// LetsEncryptConfig configures Let's Encrypt certificate provisioning. Certificates
// and their persistent keys are stored in the shared storage.Backend.
type LetsEncryptConfig struct {
	Email               string
	Domains             []string
	DefaultDomain       string
	SyncIntervalMinutes int    // renewal-check + follower refresh interval (default 5)
	Staging             bool   // use Let's Encrypt staging environment (issued certs untrusted)
	RenewBeforeDays     int    // days before expiry to renew (0 = default 30)
	MaxRetriesPerHour   int    // max failed issuance attempts per domain per hour (0 = default 3)
	KeyType             string // "ecdsa-p256" (default) or "rsa-2048"
	DANE                DANEConfig
}

// DANEConfig configures DANE TLSA record computation for inbound SMTP (port 25).
// A non-empty MXHosts enables it. The manager never writes DNS; the operator
// publishes the computed records and the manager verifies them read-only.
type DANEConfig struct {
	MXHosts    []string
	TTLSeconds int
}

// Manager orchestrates self-driven Let's Encrypt issuance with caller-owned,
// persistent per-domain keys, so every renewal reuses the same key and the leaf's
// SPKI (and its DANE digest) never changes.
type Manager struct {
	keyStore   *KeyStore
	issuer     *Issuer
	certCache  *certCache
	challenges *ChallengeServer
	dane       *daneController
	logger     *slog.Logger

	domains       []string
	domainSet     map[string]bool
	defaultDomain string
	email         string
	staging       bool
	renewBefore   time.Duration
	checkInterval time.Duration
	isLeaderF     func() bool

	onDemand *onDemand // dynamic allow-set (nil when not configured)

	tlsConfig   *tls.Config
	leaser      *issueLeaser // cluster-wide issuance lease (split-brain guard)
	retries     *retryBudget // per-domain failed-attempt cap (CA rate-limit guard)
	onDANEMatch func(host string, matched bool)

	issuerMu sync.Mutex // guards lazy issuer creation
	inflight keyedMutex // per-domain issuance dedupe
	issuing  sync.Map   // domain -> struct{}: in-flight async issuance dedupe
	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewManager creates a TLS manager. backend is the shared storage backend; prefix
// is the storage base prefix (e.g. cfg.Storage.S3Prefix). If isLeaderF is provided
// and non-nil, only the cluster leader mints keys and talks to the CA.
func NewManager(ctx context.Context, cfg *Config, backend storage.Backend, prefix string, logger *slog.Logger, isLeaderF ...func() bool) (*Manager, error) {
	if !cfg.Enabled || cfg.Provider != "letsencrypt" {
		return nil, nil
	}
	if backend == nil {
		return nil, fmt.Errorf("tls: storage backend is required for letsencrypt provider")
	}

	var leaderFunc func() bool
	if len(isLeaderF) > 0 && isLeaderF[0] != nil {
		leaderFunc = isLeaderF[0]
		logger.Info("TLS: cluster mode — only the leader will obtain certificates")
	} else {
		logger.Info("TLS: single-instance mode (no cluster leader election)")
	}

	le := cfg.LetsEncrypt
	keyType := le.KeyType
	if keyType == "" {
		keyType = KeyTypeECDSAP256
	}

	keyStore := NewKeyStore(backend, prefix, keyType, leaderFunc, logger)
	// Challenge tokens are mirrored to shared storage so any node can answer the CA
	// even though only the leader drives the order (shared/gossiped MX hostname).
	challenges := NewChallengeServer(backend, prefix, logger)
	// Refresh rebuilds a cert from the durable chain + the persistent key; the key
	// always exists by the time a chain does, so this is load-only (never mints).
	cc := newCertCache(backend, prefix, keyStore.LoadCertKey, logger)

	renewBefore := 30 * 24 * time.Hour
	if le.RenewBeforeDays > 0 {
		renewBefore = time.Duration(le.RenewBeforeDays) * 24 * time.Hour
	}
	checkInterval := time.Duration(le.SyncIntervalMinutes) * time.Minute
	if checkInterval <= 0 {
		checkInterval = 5 * time.Minute
	}

	// Default to 3 attempts/hour: safely under Let's Encrypt's 5 failed
	// validations per hostname per hour, so a persistent failure never exhausts
	// the CA-side budget.
	maxRetries := le.MaxRetriesPerHour
	if maxRetries <= 0 {
		maxRetries = 3
	}

	defaultDomain := le.DefaultDomain
	if defaultDomain == "" && len(le.Domains) > 0 {
		defaultDomain = le.Domains[0]
	}

	domainSet := make(map[string]bool, len(le.Domains))
	for _, d := range le.Domains {
		domainSet[strings.ToLower(d)] = true
	}

	var daneCtl *daneController
	if len(le.DANE.MXHosts) > 0 {
		ttl := uint32(le.DANE.TTLSeconds)
		if ttl == 0 {
			ttl = 3600
		}
		// Soak = how long the previous digest stays published after a key
		// replacement: long enough for lagging nodes (≤ renewal/refresh interval) to
		// pick up the new cert AND for DNS (TTL) to propagate, with margin.
		soak := checkInterval
		if dnsTTL := time.Duration(ttl) * time.Second; dnsTTL > soak {
			soak = dnsTTL
		}
		soak *= 2
		if soak < 10*time.Minute {
			soak = 10 * time.Minute
		}
		daneCtl = newDANEController(keyStore, backend, prefix, le.DANE.MXHosts, ttl, soak, logger)
		// Read-only verification of the published records: drift alarm each
		// maintenance tick plus the issuance/activation gates. Always on with
		// DANE — it needs no credentials and never writes DNS.
		dnsTimeout := time.Duration(cfg.DNSTimeoutSeconds) * time.Second
		daneCtl.lookup = dane.NewResolverLookup(cfg.DNSResolvers, dnsTimeout)
		logger.Info("TLS: DANE TLSA computation enabled (port 25)", "mx_hosts", le.DANE.MXHosts, "ttl", ttl, "soak", soak, "verify_published", true)
	}

	nodeID := randNodeID()
	m := &Manager{
		keyStore:      keyStore,
		certCache:     cc,
		challenges:    challenges,
		dane:          daneCtl,
		leaser:        &issueLeaser{backend: backend, prefix: prefix, nodeID: nodeID, ttl: issueLeaseTTL, logger: logger},
		retries:       newRetryBudget(maxRetries),
		onDANEMatch:   cfg.OnDANEPublishedMatch,
		logger:        logger,
		domains:       le.Domains,
		domainSet:     domainSet,
		defaultDomain: defaultDomain,
		email:         le.Email,
		staging:       le.Staging,
		renewBefore:   renewBefore,
		checkInterval: checkInterval,
		isLeaderF:     leaderFunc,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	if cfg.OnDemand != nil {
		m.onDemand = newOnDemand(*cfg.OnDemand, backend, prefix)
	}
	m.tlsConfig = m.buildTLSConfig()

	// Preload any certs already in storage so we can serve immediately, then run
	// maintenance (leader: issue/renew; follower: refresh) in the background.
	m.preload(ctx)
	// The allow-set is fetched BEFORE the first maintenance pass so a restarting
	// node issues/renews its on-demand hostnames on that pass rather than idling
	// a full interval; it is also its own loop, at its own (faster) cadence.
	m.refreshAllowSetIfConfigured(ctx)
	m.startOnDemand()
	m.startMaintenance()

	logger.Info("TLS manager initialized",
		"domains", le.Domains,
		"email", le.Email,
		"default_domain", defaultDomain,
		"key_type", keyType,
		"dane_mx_hosts", le.DANE.MXHosts,
		"max_retries_per_hour", maxRetries,
		"node_id", nodeID)
	return m, nil
}

func (m *Manager) isLeader() bool {
	return m.isLeaderF == nil || m.isLeaderF()
}

// refreshAllowSetIfConfigured does one synchronous allow-set fetch during
// construction, bounded so a slow or down control plane delays startup by
// seconds rather than blocking it: an empty allow-set only means on-demand
// hostnames are refused until the first loop tick, while the platform's own
// static domains are unaffected.
func (m *Manager) refreshAllowSetIfConfigured(ctx context.Context) {
	if m.onDemand == nil {
		return
	}
	loadCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if m.isLeader() {
		m.onDemand.hydrateIndex(loadCtx)
		m.onDemand.refreshLeader(loadCtx, m.logger)
		return
	}
	if err := m.onDemand.refreshFollower(loadCtx); err != nil {
		m.logger.Debug("TLS: no published on-demand allow-set yet", "error", err)
	}
}

// ensureIssuer lazily builds the ACME issuer (and registers the account) the first
// time the leader needs to issue. Followers never call this.
func (m *Manager) ensureIssuer(ctx context.Context) (*Issuer, error) {
	m.issuerMu.Lock()
	defer m.issuerMu.Unlock()
	if m.issuer != nil {
		return m.issuer, nil
	}
	accountKey, err := m.keyStore.LoadOrCreateAccountKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("load ACME account key: %w", err)
	}
	m.issuer = NewIssuer(accountKey, m.email, m.staging, m.challenges, m.logger)
	return m.issuer, nil
}

// buildTLSConfig constructs the tls.Config served to SMTP listeners and the
// dedicated :443 TLS-ALPN-01 challenge server. The GetCertificate guards mirror
// the previous autocert wiring (SNI default, case-fold, IP rejection, host
// whitelist, incomplete-chain warning).
func (m *Manager) buildTLSConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Advertise the ACME ALPN proto so the :443 challenge server can complete
		// TLS-ALPN-01. SMTP listeners clear NextProtos in initTLS.
		NextProtos: []string{acme.ALPNProto},
	}
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName := hello.ServerName

		// TLS-ALPN-01 challenge: the CA negotiates only "acme-tls/1" and expects
		// the in-memory token certificate.
		if isALPNChallenge(hello) {
			if cert, ok := m.challenges.GetALPN(strings.ToLower(serverName)); ok {
				return cert, nil
			}
			return nil, fmt.Errorf("%w: no tls-alpn-01 challenge in progress for %s", ErrCertificateUnavailable, serverName)
		}

		serverName = strings.ToLower(serverName) // RFC 4343: DNS names are case-insensitive

		// A sender that omits SNI, or puts an IP literal in it (RFC 6066 forbids IP
		// SNI, but some MTAs send it anyway), hasn't named a certificate we can serve.
		// Fall back to the default domain's cert instead of hard-failing the
		// handshake — failing breaks opportunistic inbound TLS and surfaces on the
		// sender as "Failed to init TLS". The default domain is substituted before
		// the domain whitelist check, so a bogus SNI can never trigger issuance.
		if serverName == "" || isIPAddress(serverName) {
			if m.defaultDomain == "" {
				m.logger.Debug("TLS: no usable SNI and no default domain configured", "sni", hello.ServerName)
				return nil, ErrMissingServerName
			}
			m.logger.Debug("TLS: missing or IP-literal SNI - using default domain",
				"sni", hello.ServerName, "default_domain", m.defaultDomain)
			serverName = strings.ToLower(m.defaultDomain)
		}

		// The static whitelist first, then the dynamic allow-set. BOTH are pure
		// memory: an SNI in neither is refused here without a single byte of I/O,
		// which is what makes a flood of invented server names free — no storage
		// read, no control-plane query, and above all no CA order.
		onDemandHost := false
		if !m.domainSet[serverName] {
			if m.onDemand == nil || !m.onDemand.allows(serverName) {
				return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, serverName)
			}
			onDemandHost = true
		}

		cert, err := m.getCertificate(serverName, onDemandHost)
		if err != nil {
			m.logger.Error("TLS: failed to get certificate", "server_name", serverName, "error", err)
			return nil, fmt.Errorf("%w for %s: %v", ErrCertificateUnavailable, serverName, err)
		}
		// A leaf-only chain makes strict clients (Outlook / Exchange Online) abort.
		if len(cert.Certificate) <= 1 {
			m.logger.Warn("TLS: certificate chain may be incomplete (no intermediates)", "domain", serverName)
		}
		return cert, nil
	}
	return cfg
}

// getCertificate serves a cached cert. It NEVER runs the ACME flow inline on the
// handshake goroutine: a leader cache miss kicks asynchronous issuance and returns
// "unavailable" immediately (the sending MTA retries; maintenance fills the cache),
// so a slow CA can't stall handshakes for minutes. Followers do a throttled,
// deduplicated storage refresh.
//
// ON-DEMAND hostnames get one bounded exception, when HandshakeWait is set. The
// client behind them is typically a person's mail app connecting to a hostname
// they configured seconds ago, and "connection failed, try again" is a support
// ticket where an MTA's retry is invisible. So the handshake WAITS for the
// issuance already in flight — bounded, so a slow CA costs one client one
// timeout rather than the fleet's handshake capacity, and only for names the
// allow-set already vouched for.
func (m *Manager) getCertificate(domain string, onDemandHost bool) (*tls.Certificate, error) {
	if cert, ok := m.certCache.Get(domain); ok {
		return cert, nil
	}

	wait := time.Duration(0)
	if onDemandHost && m.onDemand != nil {
		wait = m.onDemand.cfg.HandshakeWait
	}

	if m.isLeader() {
		// An on-demand hostname is not in preload() (the static list is), so a
		// leader that just restarted has a perfectly good certificate in storage
		// and nothing in memory. Ordering a new one for it would spend a CA order
		// to re-obtain what we already hold — check storage first, exactly as a
		// follower does. Static domains skip this: preload already covered them,
		// so a miss there really is "not issued yet".
		if onDemandHost {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cert, err := m.certCache.Refresh(ctx, domain)
			cancel()
			if err == nil {
				return cert, nil
			}
		}
		m.requestIssue(domain) // async, deduplicated
		if wait > 0 {
			if cert, ok := m.awaitCertificate(domain, wait); ok {
				return cert, nil
			}
		}
		return nil, fmt.Errorf("%w: issuance in progress for %s", ErrCertificateUnavailable, domain)
	}

	// Follower: dedup concurrent handshakes and throttle storage reads.
	unlock := m.inflight.lock(domain)
	defer unlock()
	if cert, ok := m.certCache.Get(domain); ok { // populated while we waited
		return cert, nil
	}
	if m.certCache.recentMiss(domain) {
		if wait > 0 {
			if cert, ok := m.awaitCertificate(domain, wait); ok {
				return cert, nil
			}
		}
		return nil, fmt.Errorf("%w: %s not yet issued by leader", ErrCertificateUnavailable, domain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cert, err := m.certCache.Refresh(ctx, domain)
	if err != nil {
		m.certCache.noteMiss(domain)
		if wait > 0 {
			if cert, ok := m.awaitCertificate(domain, wait); ok {
				return cert, nil
			}
		}
		return nil, fmt.Errorf("%w: %s not yet available (follower): %v", ErrCertificateUnavailable, domain, err)
	}
	return cert, nil
}

// awaitCertificate polls for a certificate appearing for `domain` within
// `limit`, from the in-memory cache (leader, filled by the issuance it just
// kicked) or from storage (follower, filled by the leader's issuance).
//
// Polling rather than a completion channel, deliberately: the certificate can
// arrive from ANOTHER node, so there is no local future to wait on, and a poll
// costs one small read per second against a bound measured in seconds.
func (m *Manager) awaitCertificate(domain string, limit time.Duration) (*tls.Certificate, bool) {
	deadline := time.Now().Add(limit)
	leader := m.isLeader()
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, false
		}
		sleep := time.Second
		if remaining < sleep {
			sleep = remaining
		}
		time.Sleep(sleep)
		if cert, ok := m.certCache.Get(domain); ok {
			return cert, true
		}
		if leader {
			continue // the issuance we kicked publishes into the cache directly
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cert, err := m.certCache.Refresh(ctx, domain)
		cancel()
		if err == nil {
			return cert, true
		}
	}
}

// requestIssue triggers asynchronous issuance for a domain on the leader,
// deduplicated so repeated handshakes don't spawn duplicate issuance goroutines.
func (m *Manager) requestIssue(domain string) {
	domain = strings.ToLower(domain)
	if _, inFlight := m.issuing.LoadOrStore(domain, struct{}{}); inFlight {
		return
	}
	safego.Go(m.logger, "tls-issue", func() {
		defer m.issuing.Delete(domain)
		ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
		defer cancel()
		if _, err := m.obtain(ctx, domain); err != nil {
			m.logger.Warn("TLS: background issuance failed", "domain", domain, "error", err)
		}
	})
}

// obtain issues (or re-issues) a certificate for domain reusing its persistent
// key, deduplicating concurrent requests for the same domain.
func (m *Manager) obtain(ctx context.Context, domain string) (*tls.Certificate, error) {
	domain = strings.ToLower(domain)
	unlock := m.inflight.lock(domain)
	defer unlock()

	// Another goroutine may have populated the cache while we waited.
	if cert, ok := m.certCache.Get(domain); ok {
		return cert, nil
	}

	if err := m.dane.gateIssuance(ctx, domain); err != nil {
		return nil, err
	}
	certKey, err := m.keyStore.LoadOrCreateCertKey(ctx, domain)
	if err != nil {
		return nil, err
	}
	return m.issueWithKey(ctx, domain, certKey)
}

// issueWithKey runs the ACME flow for domain with the given key and stores the
// resulting chain, serialized cluster-wide by the issuance lease so two
// believed-leaders can't drive duplicate orders. Attempts are additionally
// capped by the per-domain retry budget so a persistent failure (firewall, DNS)
// can't burn through the CA's failed-validation rate limit.
func (m *Manager) issueWithKey(ctx context.Context, domain string, certKey crypto.Signer) (*tls.Certificate, error) {
	if wait, ok := m.retries.allow(domain); !ok {
		return nil, fmt.Errorf("issuance retry budget exhausted for %s (max %d failed attempts per hour, protecting CA rate limits); next attempt allowed in %s",
			domain, m.retries.max, wait.Round(time.Second))
	}

	release, ok := m.acquireIssueLease(ctx, domain)
	if !ok {
		// Another node holds the issuance lease. Don't drive a duplicate ACME order;
		// serve the peer's result from storage if it's there yet.
		m.logger.Info("TLS: issuance deferred — lease held by another node", "domain", domain)
		if cert, err := m.certCache.Refresh(ctx, domain); err == nil {
			return cert, nil
		}
		return nil, fmt.Errorf("issuance in progress on another node for %s", domain)
	}
	defer release()

	// Re-check storage now that we hold the lease: a peer that just released it may
	// already have produced a still-fresh certificate, so we must not re-issue.
	if cert, err := m.certCache.Refresh(ctx, domain); err == nil {
		if na, ok := m.certCache.leafNotAfter(domain); ok && time.Until(na) > m.renewBefore {
			m.logger.Debug("TLS: skipping issuance — peer already produced a fresh cert", "domain", domain)
			return cert, nil
		}
	}

	issuer, err := m.ensureIssuer(ctx)
	if err != nil {
		m.retries.recordFailure(domain)
		return nil, err
	}
	chainPEM, err := issuer.Issue(ctx, domain, certKey)
	if err != nil {
		m.retries.recordFailure(domain)
		return nil, err
	}
	cert, err := m.certCache.Store(ctx, domain, chainPEM, certKey)
	if err != nil {
		// The order was already consumed; a retry drives a fresh one, so a
		// persistent storage failure must also back off.
		m.retries.recordFailure(domain)
		return nil, err
	}
	m.retries.reset(domain)
	return cert, nil
}

// acquireIssueLease takes the cluster-wide issuance lease for domain, returning a
// release func and whether it was acquired. Nil-safe for tests/single-node.
func (m *Manager) acquireIssueLease(ctx context.Context, domain string) (func(), bool) {
	if m.leaser == nil {
		return func() {}, true
	}
	return m.leaser.acquire(ctx, domain)
}

// preload loads any already-issued certs from storage into memory so the server
// can serve before maintenance runs. Best-effort.
func (m *Manager) preload(ctx context.Context) {
	loadCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, d := range m.domains {
		if _, err := m.certCache.Refresh(loadCtx, d); err != nil {
			m.logger.Debug("TLS: no preexisting certificate to preload", "domain", d, "error", err)
		} else {
			m.logger.Info("TLS: preloaded certificate from storage", "domain", d)
		}
	}
}

// TLSConfig returns a clone of the TLS configuration for HTTP/SMTP servers.
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil || m.tlsConfig == nil {
		return nil
	}
	return m.tlsConfig.Clone()
}

// HTTPHandler returns the HTTP-01 challenge handler for the :80 / health servers.
func (m *Manager) HTTPHandler() http.Handler {
	if m == nil {
		return nil
	}
	return m.challenges.HTTPHandler()
}

// CertificateInfo describes a certificate's validity window.
type CertificateInfo struct {
	Domain          string
	NotBefore       time.Time
	NotAfter        time.Time
	DaysUntilExpiry int
	IsExpired       bool
	Error           error
}

// GetCertificateInfo reports the current certificate state for a domain.
func (m *Manager) GetCertificateInfo(domain string) CertificateInfo {
	info := CertificateInfo{Domain: domain}
	if m == nil {
		info.Error = fmt.Errorf("TLS manager not initialized")
		return info
	}
	cert, ok := m.certCache.Get(domain)
	if !ok {
		// Attempt a storage refresh before reporting unavailable.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var err error
		cert, err = m.certCache.Refresh(ctx, domain)
		if err != nil {
			info.Error = fmt.Errorf("no certificate available for %s: %w", domain, err)
			return info
		}
	}
	if cert.Leaf != nil {
		info.NotBefore = cert.Leaf.NotBefore
		info.NotAfter = cert.Leaf.NotAfter
		info.DaysUntilExpiry = int(time.Until(cert.Leaf.NotAfter).Hours() / 24)
		info.IsExpired = time.Now().After(cert.Leaf.NotAfter)
	}
	return info
}

// CheckCertificates logs the status of every configured domain.
func (m *Manager) CheckCertificates() {
	if m == nil {
		return
	}
	m.logger.Info("checking certificate status for all domains")
	for _, domain := range m.domains {
		info := m.GetCertificateInfo(domain)
		switch {
		case info.Error != nil:
			m.logger.Warn("certificate check failed", "domain", domain, "error", info.Error)
		case info.IsExpired:
			m.logger.Error("certificate EXPIRED", "domain", domain, "expired_at", info.NotAfter)
		case info.DaysUntilExpiry <= 30:
			m.logger.Info("certificate expiring soon", "domain", domain, "days_remaining", info.DaysUntilExpiry)
		}
	}
}

// RenewCertificate re-issues a domain's certificate reusing its persistent key, so
// the SPKI (and any DANE TLSA record) is unchanged. Must run on the leader.
func (m *Manager) RenewCertificate(domain string) ([]string, error) {
	if m == nil {
		return nil, fmt.Errorf("TLS manager not initialized")
	}
	if !m.isLeader() {
		return nil, fmt.Errorf("certificate renewal must be performed on the cluster leader node")
	}
	domain = strings.ToLower(domain)
	if !m.domainSet[domain] {
		return nil, fmt.Errorf("domain %q is not in the configured domain list", domain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), issueTimeout)
	defer cancel()

	unlock := m.inflight.lock(domain)
	defer unlock()

	// Manual renewal is the documented override for the DANE issuance gate:
	// surface what the gate would have blocked, but proceed.
	if err := m.dane.gateIssuance(ctx, domain); err != nil {
		m.logger.Warn("TLS: DANE gate would block automatic issuance — proceeding (manual renewal overrides)", "domain", domain, "reason", err)
	}
	certKey, err := m.keyStore.LoadOrCreateCertKey(ctx, domain)
	if err != nil {
		return nil, err
	}
	if _, err := m.issueWithKey(ctx, domain, certKey); err != nil {
		return nil, fmt.Errorf("renew %s: %w", domain, err)
	}
	m.logger.Info("certificate renewed (key reused — SPKI unchanged)", "domain", domain)
	return []string{domain}, nil
}

// DesiredTLSARecords returns the DANE TLSA records the operator should publish for
// the configured MX hosts. Empty when DANE is disabled.
func (m *Manager) DesiredTLSARecords(ctx context.Context) ([]dane.TLSARecord, error) {
	if m == nil || m.dane == nil {
		return nil, nil
	}
	return m.dane.DesiredRecords(ctx)
}

// Stop shuts down the maintenance loop.
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
		select {
		case <-m.doneCh:
		case <-time.After(10 * time.Second):
			m.logger.Warn("TLS: maintenance loop did not stop in time")
		}
	})
}

func isALPNChallenge(hello *tls.ClientHelloInfo) bool {
	return len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto
}

// isIPAddress reports whether host parses as an IP literal.
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// keyedMutex provides per-key mutual exclusion for issuance dedupe.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*sync.Mutex)
	}
	mu, ok := k.m[key]
	if !ok {
		mu = &sync.Mutex{}
		k.m[key] = mu
	}
	k.mu.Unlock()
	mu.Lock()
	return mu.Unlock
}
