// Package certmanager provides clustered, self-driven Let's Encrypt certificate
// provisioning for mail servers (SMTP/IMAP/POP3 gateways) with DANE-stable
// persistent keys.
//
// Unlike autocert, issuance is fully explicit: certificates are issued via
// x/crypto/acme (TLS-ALPN-01 preferred, HTTP-01 fallback) against caller-owned,
// persistent per-domain private keys stored in a shared storage.Backend
// (S3/R2-compatible or filesystem). Reusing the key on every renewal keeps the
// leaf's SubjectPublicKeyInfo — and therefore its DANE "3 1 1" TLSA digest —
// stable forever.
//
// Multi-node coordination is layered:
//
//   - a caller-supplied leader predicate (e.g. memberlist-based) soft-gates
//     issuance so only one node normally talks to the CA;
//   - a per-domain issuance lease, taken by atomic create-once (IfNoneMatch:"*")
//     in the storage backend and taken over, once expired, by one conditional
//     write against its ETag, hard-guards against split-brain double-issuance;
//   - every decision to order treats a failed storage read as "cannot tell",
//     never as "nothing there": only a definite not-found leads to an order;
//   - the order in flight is journaled before it is placed, so an attempt
//     interrupted after the CA issued collects the certificate next time
//     instead of ordering again;
//   - challenge tokens are mirrored to storage so whichever node the CA
//     validates against can answer, even though another node drove the order;
//   - followers never contact the CA: they serve certificates the leader
//     persisted, refreshing from storage on a poll interval and on handshake
//     misses.
//
// A proactive maintenance loop issues missing certificates and renews inside
// the renewal window; the TLS handshake path never runs ACME inline. A
// per-domain retry budget keeps persistent local failures from exhausting the
// CA's failed-validation rate limits.
//
// See the repository README for the full architecture and INTEGRATION.md for a
// step-by-step adoption guide.
package certmanager
