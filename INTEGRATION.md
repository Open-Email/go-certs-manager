# Integration guide

How to wire `go-certs-manager` into an Open-Email edge server (`smtp-in`,
`smtp-out`, `gateway`, or a new service). The module owns certificate
provisioning; the host owns config parsing, the storage client, cluster
membership, listeners, and metrics.

```
go get github.com/Open-Email/go-certs-manager
```

The repo is private: builds need `GOPRIVATE=github.com/Open-Email/*` (already
standard across Open-Email repos) and git credentials for the org.

## 1. Storage backend

Every node must share one backend (this is what makes clustering work — certs,
keys, challenge tokens, and the issuance lease all live here).

**S3 / Cloudflare R2 (clusters):**

```go
import (
    awsconfig "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/Open-Email/go-certs-manager/storage"
)

s3c := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("https://<account>.r2.cloudflarestorage.com")
    o.UsePathStyle = true // R2 / MinIO / B2
})
backend := storage.NewS3Backend(s3c, "openemail-certs", logger)
```

**Filesystem (single node / dev):**

```go
backend, err := storage.NewFilesystemBackend("/var/lib/<svc>/certstate", logger)
```

> The backend's conditional put (`IfNoneMatch: "*"`) must be atomic — both
> shipped backends are. R2 supports it natively. If you point this at another
> S3-compatible store, verify it honors `If-None-Match: *` (MinIO ≥ RELEASE.
> 2024-08 does; some gateways silently ignore it, which breaks the lease and
> key create-once).

## 2. Leader predicate (clusters only)

Any `func() bool`. The existing memberlist-based election (lexicographically
smallest node name) in each repo is exactly what this was designed for:

```go
var isLeader func() bool
if clusterMgr != nil {
    isLeader = clusterMgr.IsLeader
}
```

Omit it (or pass nil) for single-node: the node is then always allowed to
issue. The predicate is a *soft* gate — the storage lease is the hard guard —
so an occasionally-wrong predicate is safe, just noisier.

## 3. Manager

```go
import certmanager "github.com/Open-Email/go-certs-manager"

mgr, err := certmanager.NewManager(ctx, &certmanager.Config{
    Enabled:  true,
    Provider: "letsencrypt",
    LetsEncrypt: certmanager.LetsEncryptConfig{
        Email:               cfg.TLS.LetsEncrypt.Email,
        Domains:             cfg.TLS.LetsEncrypt.Domains,       // exact host whitelist
        DefaultDomain:       cfg.TLS.LetsEncrypt.DefaultDomain, // SNI fallback; default = Domains[0]
        SyncIntervalMinutes: cfg.TLS.LetsEncrypt.SyncIntervalMinutes, // default 5
        Staging:             cfg.TLS.LetsEncrypt.Staging,
        RenewBeforeDays:     cfg.TLS.LetsEncrypt.RenewBeforeDays,     // default 30
        MaxRetriesPerHour:   cfg.TLS.LetsEncrypt.MaxRetriesPerHour,   // default 3
        KeyType:             cfg.TLS.LetsEncrypt.KeyType,             // "ecdsa-p256" | "rsa-2048"
        DANE: certmanager.DANEConfig{ // optional; SMTP port-25 servers only
            MXHosts:    cfg.TLS.LetsEncrypt.DANE.MXHosts,
            TTLSeconds: cfg.TLS.LetsEncrypt.DANE.TLSADNSTTLSeconds,
        },
    },
    DNSResolvers:      cfg.DNS.Resolvers,       // for read-only TLSA verification
    DNSTimeoutSeconds: cfg.DNS.TimeoutSeconds,
    OnDANEPublishedMatch: func(host string, matched bool) { // optional metrics hook
        v := 0.0
        if matched { v = 1.0 }
        metrics.DANETLSAPublishedMatch.WithLabelValues(host).Set(v)
    },
}, backend, cfg.Storage.S3Prefix, logger, isLeader)
```

Semantics to know:

- `Enabled: false` or `Provider != "letsencrypt"` returns `(nil, nil)` — a nil
  `*Manager` is safe to call methods on (`TLSConfig()`/`HTTPHandler()` return
  nil), so the host can wire unconditionally.
- `NewManager` preloads existing certs from storage and starts the maintenance
  loop; call `mgr.Stop()` on shutdown.
- `prefix` is the storage key prefix shared with the rest of your deployment's
  objects (e.g. `cfg.Storage.S3Prefix`); pass `""` for none.
- `KeyType` must stay constant once keys exist.

## 3b. On-demand hostnames (multi-tenant vanity names)

If customers bring their own hostnames, give the manager an enumerator instead
of extending `Domains` (which is static and needs a restart):

```go
OnDemand: &certmanager.OnDemandConfig{
    // Called on the LEADER only, every Interval. Make it cheap — a conditional
    // request against your control plane. An error keeps the last good set.
    Enumerate: func(ctx context.Context) ([]string, error) {
        return coreClient.ListVerifiedHostnames(ctx, "mail")
    },
    ExpectedTarget: cfg.TLS.LetsEncrypt.Domains[0], // what customers CNAME at
    HandshakeWait:  20 * time.Second,               // interactive clients
},
```

Two rules for the authority behind `Enumerate`:

- **Return only hostnames whose DNS you have verified points at you.** The
  module's DNS pre-flight is a second line of defence, not the first: a set full
  of unpointed names still costs a lookup each and delays the ones that work.
- **Never let the enumeration be a per-hostname question.** The whole
  rate-limit story rests on the allow-set being pushed; adding a
  "is this SNI allowed?" call to the handshake path reintroduces exactly the
  amplification this design removes.

Followers need no credentials for the control plane — they read the set the
leader published to shared storage.

## 4. Challenge listeners (every node)

Both listeners run on **all** nodes — the CA may validate against any of them.
Start them only when `mgr != nil`.

```go
// TLS-ALPN-01 (preferred). Uses the manager's own TLS config, which advertises
// "acme-tls/1"; GetCertificate serves the token cert.
safego.Go(logger, "acme-tls-alpn", func() {
    srv := &http.Server{Addr: ":443", TLSConfig: mgr.TLSConfig()}
    _ = srv.ListenAndServeTLS("", "")
})

// HTTP-01 (fallback).
safego.Go(logger, "acme-http", func() {
    _ = http.ListenAndServe(":80", mgr.HTTPHandler())
})
```

If the host already runs an HTTP server on :80 (health/API), mount the handler
instead: `mux.Handle("/.well-known/acme-challenge/", mgr.HTTPHandler())`.

If :443 cannot be bound (something else owns it), don't start the ALPN server —
the issuer automatically falls back to HTTP-01 when the ALPN authorization
isn't offered or fails; but note Let's Encrypt offers both, and the issuer
*prefers* tls-alpn-01, so with no :443 listener the first attempt burns a
failed validation. Either bind :443 or front it so `acme-tls/1` reaches this
process.

## 5. Protocol-facing tls.Config

`mgr.TLSConfig()` returns a fresh clone each call — mutate it freely for the
protocol listener without affecting the challenge server:

```go
tlsConf := mgr.TLSConfig()
tlsConf.MinVersion = tls.VersionTLS12
tlsConf.NextProtos = nil               // REQUIRED for SMTP/IMAP/POP3: a non-empty
                                       // ALPN list breaks strict clients (Exchange Online)
tlsConf.SessionTicketsDisabled = true  // TLS 1.3 NewSessionTicket after handshake
                                       // breaks Exchange Online / Outlook on SMTP
```

For IMAP/POP3 the `SessionTicketsDisabled` compat hack is not needed; set
`NextProtos` to whatever the listener negotiates (or nil).

Handshake errors you may observe (all `errors.Is`-able):

| Error | Meaning |
|---|---|
| `ErrCertificateUnavailable` | not issued yet / transient (storage, CA); leader has kicked async issuance |
| `ErrMissingServerName` | no SNI and no `DefaultDomain` configured |
| `ErrHostNotAllowed` | SNI outside `Domains` |
| `ErrKeyCertMismatch` | transient chain/key inconsistency during a key ceremony; self-heals |

## 6. File provider (non-ACME deployments)

For `provider = "file"` keep using the module's `FileCertProvider`:

```go
p, err := certmanager.NewFileCertProvider(certFile, keyFile, logger)
tlsConf := &tls.Config{GetCertificate: p.GetCertificate, MinVersion: tls.VersionTLS12}
// on SIGHUP: p.Reload()
```

## 7. Admin / operational surface

For admin CLIs (`smtp-in-admin` etc.):

- `mgr.GetCertificateInfo(domain)` / `mgr.CheckCertificates()` — expiry status.
- `mgr.RenewCertificate(domain)` — manual renewal (leader-only; bypasses the
  DANE issuance gate with a warning).
- `mgr.DesiredTLSARecords(ctx)` — zone lines the operator must publish.
- Key-replacement ceremony (leader-only):
  1. `mgr.ReplaceCertificateKey(domain)` → publish returned TLSA records
  2. wait for DNS TTL propagation
  3. `mgr.ActivateCertificateKey(domain, force)` — gated on the staged record
     being visible in DNS (`force` skips, e.g. split-horizon)
  4. after the soak window (logged), retire the old TLSA record
- Raw storage inspection: read `certs/<domain>`, `keys/<domain>` via the
  `storage.Backend` — object layout is documented in the README.

## 8. Config schema (recommended TOML)

To converge the three repos, adopt smtp-in's shape:

```toml
[storage]
backend = "s3"              # "s3" (clusters) | "filesystem" (single node)
s3_endpoint = "https://<account>.r2.cloudflarestorage.com"
s3_bucket = "openemail-certs"
s3_region = "auto"
s3_prefix = ""
s3_access_key = ""          # or env S3_ACCESS_KEY / S3_SECRET_KEY
s3_secret_key = ""
filesystem_path = "/var/lib/<svc>/certstate"

[tls]
enabled = true
provider = "letsencrypt"    # "file" | "letsencrypt"

[tls.file]
cert_file = ""
key_file = ""

[tls.letsencrypt]
email = "postmaster@example.com"
domains = ["mx.example.com"]
default_domain = "mx.example.com"
sync_interval_minutes = 5
staging = false
renew_before_days = 30
max_retries_per_hour = 3
key_type = "ecdsa-p256"

[tls.letsencrypt.dane]      # SMTP port-25 servers only
mx_hosts = []
tlsa_dns_ttl_seconds = 3600

[cluster]
enabled = false
# addr/port/peers/node_name/secret_key — host-owned memberlist config
```

Mapping notes for current repos:

- **smtp-in**: 1:1 — this schema is smtp-in's.
- **smtp-out**: replace `[tls.letsencrypt] storage_provider/cache_dir` +
  `[tls.letsencrypt.s3]` with the top-level `[storage]` section; drop the
  autocert cache/sync-worker config. The cert bucket may stay separate from the
  dedup bucket.
- **gateway**: replaces the (never-wired) `[tls.letsencrypt.s3]`,
  `renew_before`, `sync_interval` keys; `fallback_dir` maps to
  `filesystem_path` with `backend = "filesystem"`. The gateway keeps its
  `gwtls` file-provider or adopts `FileCertProvider`.

## 9. Migration from autocert-based state

Existing autocert caches (DirCache or S3) are **not** read: autocert stores
key+chain concatenated under one object and regenerates keys, which is exactly
the model this module replaces. Migration = let the module issue fresh
certificates (with its own persistent keys) on first leader start-up. Plan for
one issuance per domain against production rate limits — or run once with
`staging = true` to validate wiring first.

For DANE-published domains migrating from autocert: publish TLSA for the NEW
key before cutover using `smtp-in-admin`-style tooling (`DesiredTLSARecords`
after a staging dry-run), or accept a validation gap.

## 10. Testing

- `storage/conditional_put_test.go` is the contract test for any new backend:
  32 racing conditional creates must yield exactly 1 success + 31
  `ConditionalPutError`.
- `certmanager` tests exercise the manager against `FilesystemBackend` — no
  network or CA needed; use them as wiring examples (`manager_test.go`,
  `lease_test.go`, `scheduler_test.go`).
- End-to-end against Let's Encrypt staging: `Staging: true` + a public :443/:80.
