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
                       │  orders/<domain>  (the order in flight)      │
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
   backend's atomic create-once (`IfNoneMatch: "*"`, 5-minute TTL); an expired
   lease is taken over by one conditional write against its ETag (`IfMatch`),
   so two nodes that both read it expired cannot both win. This is the
   split-brain guard: the leader predicate is unfenced (a network partition can
   produce two believed-leaders), but both sides can reach storage, so storage
   is the arbiter gossip cannot be. After acquiring, storage is re-checked for
   a peer-produced fresh cert before ordering — and **only a definite "not
   found" leads to an order**: a read that failed, a chain that did not parse
   or one bound to another key stops the attempt (`ErrStorageUnavailable`).
   That rule holds at every decision to order (maintenance, the re-check under
   the lease, the on-demand loop, the leader's handshake path).
4. The **issuer** drives RFC 8555 directly via `x/crypto/acme`: order →
   authorization → challenge → CSR built from the **persistent domain key** →
   finalize. TLS-ALPN-01 is preferred, HTTP-01 the fallback. The order's URL is
   **journaled** (`orders/<domain>`) before anything the CA can charge for;
   an attempt interrupted after issuance — a deploy restart, a deadline, a
   reset connection on the download — is collected by the next attempt instead
   of repeated. The CA counts an order the moment it signs.
5. Challenge tokens are **mirrored to storage** (`challenges/…`) so whichever
   node the CA happens to validate against can answer — required behind a
   load balancer or round-robin MX. A token that could not be mirrored is not
   presented: the validation would be one the CA may fail, and count.
6. The issued chain is persisted to `certs/<domain>` (PEM, leaf first —
   **without** the private key, which lives only in `keys/`), and installed in
   the in-memory cache.

### Handshake path (all nodes)

`Manager.TLSConfig().GetCertificate`:

- answers TLS-ALPN-01 challenges from the in-memory/mirrored token cert — for
  names in the allow-list only, so an `acme-tls/1` hello for any other name is
  refused without a storage read;
- lowercases the SNI (RFC 4343), substitutes `DefaultDomain` for missing or
  IP-literal SNI (common with legacy MTAs; failing would break opportunistic
  inbound TLS), rejects hosts outside the configured domain whitelist. Names
  are filed under one spelling everywhere (lower case, no trailing dot,
  punycode), so a Unicode domain in the configuration matches the A-label a
  client sends;
- serves from the in-memory cache. On a miss: the **leader** kicks async
  issuance and fails the handshake with `ErrCertificateUnavailable` (the MTA
  retries; maintenance fills the cache); a **follower** does a throttled,
  deduplicated storage refresh (3s negative-cache on misses);
- with `RSACompanion` on, serves a configured domain's RSA companion instead,
  to a client that cannot use the ECDSA certificate but can use the RSA one
  (see below). From memory only.

The handshake goroutine never talks to the CA and never blocks on ACME.

### RSA companion (optional)

`LetsEncrypt.RSACompanion` keeps a second, RSA-2048 certificate for every
configured domain next to the ECDSA one, for clients whose TLS stack predates
ECDSA: old printers, scanners and UPS cards that offer RSA key exchange
(`TLS_RSA_WITH_*`) or ECDHE_RSA and nothing else. Without it they fail every
handshake with `no cipher suite supported by both client and server`.

- **Who gets it.** Go's `ClientHelloInfo.SupportsCertificate` decides, against
  the listener's real configuration: a client that can use the ECDSA
  certificate keeps it, whatever else it offers. One refusal is overridden: a
  TLS 1.2 client that left P-256 out of `supported_groups` is still served
  ECDSA, because the handshake does not check that and succeeds.
- **RSA key exchange needs the listener's consent too.** Go's defaults have no
  `TLS_RSA_WITH_*` suite since 1.22, so a client offering only those also
  needs them in the listener's `tls.Config.CipherSuites` (on top of the
  secure defaults, never instead of them). ECDHE_RSA is in the defaults and
  keeps forward secrecy.
- **Storage.** Chain and key are filed as `<domain>+rsa` (`certs/`, `keys/`,
  `orders/`), and `certstore` lists the companion of a configured domain as
  configured, so `tls delete` refuses it while it is in use. The inventory is
  not told whether the option is on: after turning it off, remove a leftover
  companion with `tls delete --force <domain>+rsa`.
- **Issuance.** The leader orders and renews it in the same pass as the
  primary, only while the primary is in hand and outside its renewal window.
  It takes the domain's issuance lease and spends the domain's retry budget:
  the CA counts failed validations and duplicate certificates per hostname,
  and the TLS-ALPN-01 answer is filed by hostname. Followers re-read it every
  tick, the leader writes it back if storage loses it, and
  `RenewCertificate` does not touch it.
- **Limits.** Configured domains only, never on-demand hostnames. Not
  DANE-pinned: `DesiredTLSARecords` names the ECDSA key only, so a client that
  cannot use ECDSA and validates DANE is still refused, now at verification
  instead of at the handshake. Not reported through `OnServedExpiry`, whose
  series are per hostname. Requires `KeyType` `ecdsa-p256`.

### Key management

`KeyStore` persists PKCS#8 PEM keys in storage:

| Object | Meaning |
|---|---|
| `acme/account.key` | one cluster-wide ACME account key (always ECDSA P-256) |
| `keys/<domain>` | persistent per-domain certificate key (`ecdsa-p256` default, or `rsa-2048`), **reused on every renewal** |
| `keys/<domain>.next` | staged key during a key-replacement ceremony |
| `keys/<domain>+rsa` | the RSA companion's persistent key (`RSACompanion`), always `rsa-2048` |

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

### On-demand hostnames (optional)

Set `Config.OnDemand` and the fixed `Domains` whitelist gains a **dynamic
allow-set** enumerated from an external authority — the shape a multi-tenant
platform needs, where customers add vanity hostnames continuously and no config
file can list them. The static list keeps its meaning: those are the platform's
own names, always allowed, never dependent on the control plane being reachable.

```go
OnDemand: &certmanager.OnDemandConfig{
    Enumerate:      func(ctx context.Context) ([]string, error) { ... },
    Interval:       time.Minute,        // default 60s
    ExpectedTarget: "mail.open.email",  // DNS pre-flight target
    HandshakeWait:  20 * time.Second,   // 0 = original async behaviour
}
```

A certificate authority's rate limits are a **shared, account-wide resource**,
so the design question is not "can we issue for more names" but "can one name
spend everyone's budget". Four mechanisms, layered so each catches what the
previous cannot:

1. **The allow-set is pushed, never queried per handshake.** The leader
   enumerates and publishes to `ondemand/hosts.json`; followers read that one
   small object. `GetCertificate` consults an in-memory set, so an SNI outside
   it is refused with **no I/O at all** — a flood of invented server names costs
   no storage read, no control-plane query, and no CA order.
2. **A DNS pre-flight before EVERY order — renewals included.** The hostname
   must actually resolve to `ExpectedTarget` (by CNAME chain, or by sharing an
   address with it). The common failure — a customer who has not published the
   CNAME yet, or removed it — then costs **zero** CA budget instead of a failed
   validation, and is backed off 24h rather than re-queried every tick. A name
   that does not exist at all (NXDOMAIN, or no address records) is a DEFINITE
   miss and enters that backoff; only a resolver *failure* (SERVFAIL, timeout)
   fails open, because the CA validates independently and a working hostname
   must not be locked out for a day over one bad answer. Renewals matter here
   because a hostname leaves the allow-set only when the authority notices its
   DNS changed — a deleted record is invisible to it — so a renewal for an
   abandoned name would otherwise retry, and fail, for as long as the name is
   enumerated. (v0.5.2; earlier versions pre-flighted first issuances only.)
3. **A new-order token bucket** (`MaxNewOrdersPerHour`, default 40) bounds first
   issuances per node per hour, so a thousand-hostname import drains over hours
   instead of exhausting the account's new-order limit in minutes. Sized so that
   even two believed-leaders in a split-brain stay under Let's Encrypt's 300
   new orders per account per 3 hours.
4. **Renewals are scheduled ahead of first issuances**, because when the budget
   is scarce a working service staying up beats a new one starting.

Maintenance for on-demand hostnames differs from the static loop in three ways
that only matter at scale: every host gets its **own context** (one shared
deadline would make later hosts fail with `context deadline exceeded` and charge
that against their retry budgets), issuance runs **bounded-concurrent**
(`MaxConcurrentOrders`, default 4), and followers refresh only what the leader's
`ondemand/certs-index.json` says **changed** — O(1) storage reads per tick
rather than one per hostname.

The handshake path enforces the SAME pre-flight and order budget as the
maintenance loop. That is not defensive duplication: a handshake is triggered by
anyone who can open a TCP connection and send an SNI, so without it a bulk
onboarding drives one CA order per hostname within minutes and takes existing
customers' renewals down with the account limit.

`HandshakeWait` is the one deliberate exception to "never block a handshake".
The client behind a vanity hostname is typically a person's mail app connecting
to a name they configured seconds ago, where a failed connection is a support
ticket and an MTA's invisible retry is not available. So a handshake for an
**allowed** hostname may wait, bounded, for the issuance already in flight.
Static domains are unaffected, and 0 keeps the original behaviour.

### Local copy (optional)

`LetsEncrypt.LocalDir` keeps a copy of what this node serves on its own disk,
so a process that **starts** while storage cannot be read still has a
certificate. A running manager does not need it: it serves from memory
through an outage. Without it, a restart during one comes up with nothing to
serve until storage answers.

- **What is kept.** One file per configured domain and per companion,
  `<name>.pem`: the private key, then the chain leaf first, written by temp
  file and rename, 0600 in a 0700 directory. On-demand hostnames are not
  kept: their allow-set lives in storage too, so a restart without storage
  could not serve them anyway.
- **When it is written.** Only after storage confirmed the chain: a refresh
  that read it, an issuance that stored it, a held chain that was finally
  written. A chain the CA issued that storage has not taken is not copied.
  The file is rewritten only when its contents change.
- **When it is read.** Only at startup, and only for a name storage could
  not be read for. A definite "none" from storage, or a chain bound to
  another key (a key replacement in progress), is storage's answer and wins.
  The file is served only if the key matches the leaf, the leaf covers the
  name and has not expired; anything else is logged at warn and skipped.
- **When it stops being used.** Every maintenance tick re-reads storage for a
  name served from the copy until a read succeeds, on the leader as well: a
  leader otherwise re-reads a name it holds only when it is due for renewal.
  Nothing is ordered from the copy; ordering needs the issuance lease, which
  is a storage write.
- **DANE.** The file holds the pair the node was serving, so its SPKI is the
  one published. A node that missed a key replacement and restarts during an
  outage serves the retired key until storage answers, and a DANE-validating
  client refuses it (RFC 7672 fails closed); the first successful read
  replaces it.
- **Deciding to start.** `MissingCertificates()` lists the configured domains
  the node holds no certificate for. A host whose own storage check fails at
  startup can carry on when it is empty and stop when it is not, so a fresh
  node, or broken credentials with no copy, still fails fast.
- **Exposure.** The file is the key the process can already read from
  storage with its own credentials, on the same host under the same user. It
  adds no reader.

`NewManager` also bounds its own first contact with storage (the
conditional-write probe at 10 s, the preload at 15 s), whatever context the
caller passes, so a storage endpoint that accepts connections and never
answers cannot hold startup.

## Failure modes and guarantees

- **Split-brain**: two believed-leaders are serialized by the storage lease.
  Taking over an *expired* lease (crashed holder) is one conditional write
  against the record's ETag, so only one node wins. What remains best-effort:
  expiry is the writer's wall clock, and a holder releasing at the very moment
  its expired lease is taken over can delete the successor's (the TTL is sized
  so a live holder never gets there). `NewManager` probes the backend for
  conditional-write support and refuses to start a cluster on one that
  ignores `If-None-Match`; a single node carries on without the lease.
- **Storage down**: leases fail safe (no issuance while uncertain); handshakes
  keep serving in-memory certs; followers keep last-good certs.
- **Restart while storage is down**: nothing to serve, unless `LocalDir` is
  set and holds a usable copy (see "Local copy"). The copy is replaced by
  storage's chain on the first tick that can read it.
- **Storage reads failing while writes work**: no order. "I could not read
  it" is never "there is nothing there" — only a definite not-found leads to
  an order. The alternative was a leader restarted during a read fault
  re-ordering every certificate it held and overwriting the chains it had
  just failed to read.
- **Attempt interrupted after the CA issued**: the order is journaled before
  it is placed and collected on the next attempt (`orders/<domain>`), for the
  seven days the CA keeps it. If the journal cannot be read, no order is
  placed — the attempt cannot know whether one is outstanding.
- **CA rate limit**: the `Retry-After` the CA names is honoured across
  attempts (an hour when it names none), on top of the retry budget. Logged
  at error level with the CA's problem detail.
- **A challenge that cannot be shared**: not presented. The order fails
  before `Accept`, so the CA counts nothing.
- **Inconsistent read during ceremony**: a follower pairing the new chain with
  the not-yet-promoted old key gets `ErrKeyCertMismatch` and keeps serving its
  last-good certificate until storage is consistent.
- **CA outage / misconfig**: retry budget caps failed attempts; recovery is
  immediate once fixed (successes never consume budget).
- **Leadership flap during activation**: leadership is re-checked immediately
  before the destructive key promote; if lost, the promote aborts and the new
  leader rolls forward.
- **Control plane down (on-demand)**: the last good allow-set is kept, so
  certificates already serving traffic keep serving and keep renewing. A
  hostname added during the outage is refused until enumeration recovers.
- **Chain deleted from storage**: the leader decides whether to renew from
  its in-memory copy, so a chain removed from storage (an operator's delete, a
  bucket lifecycle rule) would go unnoticed until the renewal window, while any
  node that restarted meanwhile found nothing to serve. Each maintenance tick
  the leader lists `certs/` once and writes back any chain it serves that is
  missing — no order, since the chain is already paid for. It writes only
  after reading the object itself (a listing can skip what it could not read),
  only for names it still serves, only an unexpired chain, and only one that
  matches the key storage holds now.
- **Leader restart (on-demand)**: on-demand hostnames are not preloaded, so the
  leader loads them from the shared index before classifying work — otherwise it
  would read every one as a first issuance and spend the hour's new-order budget
  re-obtaining certificates it already holds.

## Packages

| Package | Contents |
|---|---|
| `certmanager` (root) | `Manager` (issuance, renewal, handshake `tls.Config`), `KeyStore`, `Issuer`, `ChallengeServer`, `FileCertProvider` (static cert/key with SIGHUP reload), errors |
| `storage` | `Backend` interface + `S3Backend` (aws-sdk-go-v2; any S3-compatible endpoint incl. Cloudflare R2) and `FilesystemBackend` (single node; create-once via `os.Link`). A key is a name, never a path: a `..` segment is refused |
| `dane` | SPKI digests, `TLSARecord` (zone-line rendering), retiring markers, DNSSEC-aware `TLSALookup` resolver |
| `adminapi` | The manual-renewal contract: the admin endpoint's handler and the CLI client, with their exit codes |
| `certstore` | The operator's view of certificates in storage (`Inventory`) and the `tls list/delete/clean` commands every admin CLI runs on it |

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
