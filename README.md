# go-certs-manager

Clustered, self-driven Let's Encrypt certificate provisioning for mail
infrastructure (SMTP/IMAP/POP3 gateways), with DANE-stable persistent keys.

Extracted from `smtp-in` as the shared TLS provisioning model for all
Open-Email edge servers (`smtp-in`, `smtp-out`, `gateway`).

```
import certmanager "github.com/Open-Email/go-certs-manager"
```

## Why not autocert

`golang.org/x/crypto/acme/autocert` is excellent for a single web server, but it
has properties that are wrong for a clustered mail fleet:

1. **It mints a fresh private key on every issuance.** For DANE (RFC 7672) the
   published `3 1 1` TLSA record is a digest of the certificate's public key —
   a new key on renewal silently invalidates the record and hard-fails every
   DANE-validating sender. This module issues against **caller-owned, persistent
   per-domain keys**: the SubjectPublicKeyInfo (and its DANE digest) never
   changes across renewals.
2. **Issuance is implicit and hidden.** autocert contacts the CA from inside
   `GetCertificate` on a cache miss. In a cluster that means any node can race
   an ACME order (burning Let's Encrypt rate limits), and a slow CA stalls live
   TLS handshakes. Here, issuance is explicit, leader-gated, lease-serialized,
   and **never runs inline on a handshake**.
3. **Renewal is lazy.** autocert renews when a handshake happens to hit the
   renewal window. This module runs a **proactive maintenance loop** so
   certificates renew on schedule even on idle listeners.

## Architecture

```
                       ┌──────────────────────────────────────────────┐
                       │        shared storage.Backend (S3/R2/FS)     │
                       │  acme/account.key   keys/<domain>[.next]     │
                       │  certs/<domain>     challenges/{alpn,http}/  │
                       │  locks/issue/<domain>  dane/retiring/<host>  │
                       └────────▲──────────────────▲─────────────────┘
                                │                  │
              issue / renew / lease          refresh / serve
                                │                  │
   ┌────────────────────────────┴───┐   ┌─────────┴──────────────────┐
   │ LEADER (isLeaderF() == true)   │   │ FOLLOWERS                  │
   │  · mints persistent keys       │   │  · never contact the CA    │
   │  · drives ACME orders          │   │  · refresh certs from      │
   │  · renews inside window        │   │    storage (poll + miss)   │
   │  · verifies published TLSA     │   │  · answer CA validations   │
   └────────────────────────────────┘   │    from mirrored tokens    │
                                        └────────────────────────────┘
```

### Issuance flow (leader)

1. `maintainOnce` (every `SyncIntervalMinutes`, default 5m) finds a domain with
   no certificate or one inside the renewal window (`RenewBeforeDays`, default
   30).
2. The **retry budget** is checked: at most `MaxRetriesPerHour` (default 3)
   *failed* attempts per domain per sliding hour — deliberately under Let's
   Encrypt's 5-failed-validations/hostname/hour limit, so a persistent local
   failure never exhausts the CA-side budget.
3. The **issuance lease** (`locks/issue/<domain>`) is acquired via the storage
   backend's atomic create-once (`IfNoneMatch: "*"`, 5-minute TTL). This is the
   split-brain guard: the leader predicate is unfenced (a network partition can
   produce two believed-leaders), but both sides can reach storage, so storage
   is the arbiter gossip cannot be. After acquiring, storage is re-checked for
   a peer-produced fresh cert before ordering.
4. The **issuer** drives RFC 8555 directly via `x/crypto/acme`: order →
   authorization → challenge → CSR built from the **persistent domain key** →
   finalize. TLS-ALPN-01 is preferred, HTTP-01 the fallback.
5. Challenge tokens are **mirrored to storage** (`challenges/…`) so whichever
   node the CA happens to validate against can answer — required behind a
   load balancer or round-robin MX.
6. The issued chain is persisted to `certs/<domain>` (PEM, leaf first —
   **without** the private key, which lives only in `keys/`), and installed in
   the in-memory cache.

### Handshake path (all nodes)

`Manager.TLSConfig().GetCertificate`:

- answers TLS-ALPN-01 challenges from the in-memory/mirrored token cert;
- lowercases the SNI (RFC 4343), substitutes `DefaultDomain` for missing or
  IP-literal SNI (common with legacy MTAs; failing would break opportunistic
  inbound TLS), rejects hosts outside the configured domain whitelist;
- serves from the in-memory cache. On a miss: the **leader** kicks async
  issuance and fails the handshake with `ErrCertificateUnavailable` (the MTA
  retries; maintenance fills the cache); a **follower** does a throttled,
  deduplicated storage refresh (3s negative-cache on misses).

The handshake goroutine never talks to the CA and never blocks on ACME.

### Key management

`KeyStore` persists PKCS#8 PEM keys in storage:

| Object | Meaning |
|---|---|
| `acme/account.key` | one cluster-wide ACME account key (always ECDSA P-256) |
| `keys/<domain>` | persistent per-domain certificate key (`ecdsa-p256` default, or `rsa-2048`), **reused on every renewal** |
| `keys/<domain>.next` | staged key during a key-replacement ceremony |

Creation is serialized cluster-wide by conditional create-once: a node that
loses the race reads the winner's key and **never regenerates** — every node
converges on a single key per name, which DANE depends on. Key creation is
additionally leader-gated; reads are unrestricted so followers can serve.

Keys are **not encrypted at rest** — confidentiality is delegated to the
storage backend (bucket policy / disk permissions).

### DANE support (optional)

Enabled by a non-empty `DANE.MXHosts`. The module **never writes DNS**; it
computes the desired `_25._tcp.<host>. IN TLSA 3 1 1 <spki-sha256>` records
(`DesiredTLSARecords`) and verifies the published set read-only via DNS
(drift alarm on every maintenance tick, surfaced through the
`OnDANEPublishedMatch` hook, plus two gates):

- **Issuance gate**: if TLSA records are published but no persistent key exists
  in storage (key lost), automatic issuance is *blocked* — minting a new key
  would hard-fail DANE validation. Restore the key or remove the records;
  manual renewal overrides.
- **Activation gate**: a key-replacement ceremony refuses to swap the served
  SPKI until DNS shows the staged key's TLSA record (forceable).

**Key-replacement ceremony** (e.g. after key compromise), per RFC 7671 §8:

```
ReplaceCertificateKey(domain)      // stage keys/<domain>.next; returns records to publish
  → operator publishes the new TLSA record, waits for TTL propagation
ActivateCertificateKey(domain, force) // issue with next key, serve, promote
  → after the soak window, operator retires the old TLSA record
```

The old digest is tracked as a *retiring* marker (`dane/retiring/<host>`)
through a soak window (≥ 2× max(refresh-interval, DNS TTL), min 10m) so
lagging nodes still serving the old cert don't fail validation; an interrupted
ceremony (crash between store and promote) is rolled forward idempotently by
`reconcileCeremony` on the next leader tick.

## Failure modes and guarantees

- **Split-brain**: two believed-leaders are serialized by the storage lease.
  Taking over an *expired* lease (crashed holder) has a small non-CAS race
  bounded to at most one duplicate order — accepted (blast radius is CA rate
  limits, not correctness).
- **Storage down**: leases fail safe (no issuance while uncertain); handshakes
  keep serving in-memory certs; followers keep last-good certs.
- **Inconsistent read during ceremony**: a follower pairing the new chain with
  the not-yet-promoted old key gets `ErrKeyCertMismatch` and keeps serving its
  last-good certificate until storage is consistent.
- **CA outage / misconfig**: retry budget caps failed attempts; recovery is
  immediate once fixed (successes never consume budget).
- **Leadership flap during activation**: leadership is re-checked immediately
  before the destructive key promote; if lost, the promote aborts and the new
  leader rolls forward.

## Packages

| Package | Contents |
|---|---|
| `certmanager` (root) | `Manager` (issuance, renewal, handshake `tls.Config`), `KeyStore`, `Issuer`, `ChallengeServer`, `FileCertProvider` (static cert/key with SIGHUP reload), errors |
| `storage` | `Backend` interface + `S3Backend` (aws-sdk-go-v2; any S3-compatible endpoint incl. Cloudflare R2) and `FilesystemBackend` (single node; create-once via `os.Link`) |
| `dane` | SPKI digests, `TLSARecord` (zone-line rendering), retiring markers, DNSSEC-aware `TLSALookup` resolver |

Both storage backends implement atomic create-once (`PutOptions.IfNoneMatch:
"*"` → `ConditionalPutError` on conflict); this primitive is load-bearing for
the lease and the keystore. Any new backend MUST implement it correctly
(see `storage/conditional_put_test.go`).

## Requirements

- The CA must be able to reach the servers on **:443** (TLS-ALPN-01, preferred)
  and/or **:80** (HTTP-01) for every configured domain.
- For clusters: an S3-compatible bucket reachable by all nodes, and a leader
  predicate (`func() bool`); lexicographic-min over memberlist works fine.
- Single node: `FilesystemBackend` and no leader predicate.

See [INTEGRATION.md](INTEGRATION.md) for step-by-step adoption, wiring
examples, and the operational runbook.
