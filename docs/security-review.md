# LCM security review

Constitution compliance review for the lcm module (SR-001..SR-006 and the seven
principles). Status at implementation completion.

## Security requirements

- **SR-001 — key material sealed & never returned.** CA keys, issuer/ACME/DNS
  credentials, tenant-secret values, webhook signing secrets and
  service-generated workload keys are sealed with envelope encryption
  (`internal/sealed`, AES-256-GCM DEK wrapped by the KEK) and never appear in a
  listing, credential-free export, event, webhook body or log. A generated
  workload key is delivered exactly once, at issuance. Enforced by
  `internal/sealed` redaction (`Marker`), the `View` structs (no secret fields),
  and asserted by `tests/security` (`TestSR001_*`, `TestSC002_NoKeyMaterialAnywhere`,
  `scripts/redaction-scan.sh`).
- **SR-002 — no issuance for an unentitled identity; no static secret.**
  `issue.Service.Issue` requires `use` on the issuer (Zanzibar) OR a service
  caller whose own SPIFFE identity matches the requested id; enrollment tokens
  are single-use/short-lived and authoritative only for the id they name; no
  static shared secret is ever accepted. Asserted by `TestSR002_*`.
- **SR-003 — verified SPIFFE identity on every module call.** `internal/grpcapi`
  derives the tenant and actor from the verified `authn` identity; a call
  without an identity is `Unauthenticated`. The module's `deploy/policy.yaml`
  allow-lists the peer identities per method. Asserted by
  `TestSR003_ForgedOrAbsentGRPCIdentityRejected`.
- **SR-004 — bounded inputs, scrubbed errors.** CSR (`internal/csr`,
  `MaxCSRBytes`), backup (`transfer.MaxBytes`) and webhook payloads
  (`webhook.MaxPayloadBytes`) are bounded and refused above the limit; provider,
  ACME and channel errors are scrubbed of credential values.
- **SR-005 — not_found masking.** A certificate, issuer or secret the caller may
  not read answers `not_found`, never `forbidden`, so existence is not disclosed
  across tenants or access boundaries (`httpapi.readError`, `authz.locate`).
  Asserted by `TestUS2_EntitlementMatrix` (cross-tenant → not_found).
- **SR-006 — revocation propagation.** Revoking a certificate records a
  revocation that feeds the revocation feed (`GET /revocations`) and a signed CRL
  (`GET /crl`), so the auth RevocationChecker drops a revoked SVID within the
  propagation window (`internal/revoke`).

## Principles

- **I Secure by default / II Zero-trust:** all transport is SPIFFE mTLS or the
  gateway platform token; per-object Zanzibar authz; RLS per tenant; insecure
  opt-outs (plaintext Valkey/DNS) are named and refused in production.
- **III Least privilege:** relations map to a minimal permission set; the `use`
  action gates issuance; the renewal scheduler uses a scoped system path
  (`issue.RenewSystem`), not a blanket bypass.
- **IV Tested (NON-NEGOTIABLE):** unit + contract + fuzz + negative-security
  tests per story; fuzz on CSR/SPIFFE/PEM/SSE/webhook/backup; 100% coverage on
  the credential/crypto/stream/authz packages (`scripts/coverage-gate.sh`).
- **V Observable:** closed-vocabulary batched audit with a secret-dropping detail
  guard; health route; statistics.
- **VI No custom crypto:** stdlib `crypto/x509`/`ecdsa`/`ed25519`/`aes`+`gcm`/
  `hmac`; `golang.org/x/crypto/acme` for ACME. No hand-rolled primitives.
  `gosec` clean; `govulncheck` reports no called vulnerabilities.
- **VII Bounded & resilient:** payload/stream/rate limits; distributed leases
  (`FOR UPDATE SKIP LOCKED`) for the renewal and job schedulers; best-effort
  webhook delivery with capped backoff that never blocks a request.

## Known follow-ups

- The auth-service enrollment-token mint + verify (`contracts/auth-changes.md`)
  is a cross-service change; the lcm side (single-use, id-scoped verification) is
  implemented and tested against a `TokenVerifier` interface, with a rejecting
  stub wired until the auth endpoint ships.
- The testcontainers integration suite (TimescaleDB + Valkey + Pebble/mock-DNS +
  gateway/auth subprocesses) exercises the wired httpapi/grpcapi end to end; the
  security-critical behaviours are already covered at the service level with the
  in-memory store.
- A `rotate-kek` re-seal-all-material subcommand (currently the backup
  round-trip path).
