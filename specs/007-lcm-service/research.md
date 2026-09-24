# Research: LCM — Certificate & SVID Lifecycle Management

Phase 0 decisions. Each: Decision / Rationale / Alternatives considered. The
feature touches auth, transport, parsing, secrets and crypto, so a STRIDE
threat model closes the document.

## R1 - Module shape and platform integration

**Decision**: Build `services/lcm` as a Freya module identical in shape to
warden/notification: Freya app on the mTLS channel, gateway registration via
`gatewayclient`, platform-token verification via `authclient`, TimescaleDB with
per-tenant RLS, an OpenAPI browser API validated by kin-openapi, a Vue/Vuetify
Module Federation remote, and a `deploy/policy.yaml` allow-list for
service-to-service calls.
**Rationale**: three modules already follow this shape; reuse maximises security
review leverage and consistency; nothing about a CA needs a different platform
contract.
**Alternatives**: a bespoke standalone service like tangra (rejected - would
re-implement identity, gateway, audit and the token model Freya already
provides).

## R2 - Certificate signing and ACME

**Decision**: Use the Go standard library for all X.509 work (`crypto/x509`
CreateCertificate/CreateCertificateRequest, `crypto/ecdsa` P-256 default and
`ed25519` option, `crypto/rand`). SPIFFE ids are encoded as a URI SAN
(`spiffe://<td>/<path>`) exactly as Freya's `identity`/`testutil.CA` already do.
For publicly-trusted certificates use `golang.org/x/crypto/acme` (the client) and
`github.com/go-acme/lego/v4` for the DNS-01 provider set.
**Rationale**: stdlib covers self-signed CA, intermediate, leaf and SVID minting
with no third-party code (Constitution VI); `testutil.CA` is the proven pattern
to copy for production. ACME and ten DNS providers are large, security-sensitive
protocols; `x/crypto/acme` is maintained by the Go team and `lego` is the
de-facto provider library - re-implementing either would be far riskier than
depending on them.
**Alternatives**: cfssl / step-ca / smallstep libraries (heavier, opinionated
storage and identity); hand-rolled ACME (rejected - protocol + JWS complexity);
Vault PKI (an external dependency the platform does not run).

## R3 - SVID model and entitlement

**Decision**: An SVID is an X.509 leaf whose only SAN is the SPIFFE URI
(`spiffe://<trust-domain>/<path>`), signed by the tenant CA, short-lived
(default 1 h, configurable, clamped to the issuer ceiling). A requester is
entitled to a SPIFFE path when (a) it matches its own verified caller identity
(a workload asking for its own id), or (b) the caller holds the issue/`use`
grant on the issuer/namespace, or (c) an auth-minted enrollment token names the
path. Issuance always validates the CSR public key, the requested SANs and the
path against policy.
**Rationale**: matches SPIFFE X.509-SVID conventions and Freya's existing id
shape; entitlement replaces tangra's shared secret with real authorization.
**Alternatives**: arbitrary subjects/SANs with no SPIFFE constraint (rejected -
loses the SVID guarantee and the entitlement check).

## R4 - Enrollment without a shared secret

**Decision**: Two enrollment paths, both without a static secret: (1) a workload
already holding a Freya SVID (bootstrapped once by an operator, or the dev CA)
calls `lcm.v1` over mTLS and receives/renews its SVID for its own path; (2) a
new workload presents a **short-lived enrollment token** minted by the auth
service (`auth.v1` new method, contracts/auth-changes.md) that names the tenant
and the allowed SPIFFE path(s); the LCM verifies it with `authclient` and issues
once. Auto-approve issues immediately; otherwise a certificate request is queued
for manual approval.
**Rationale**: removes the tangra shared secret (SR-002); reuses the auth service
as the single authority for who may become which identity; supports both
already-identified workloads (rotation) and cold-start bootstrap.
**Alternatives**: static per-tenant secret (the tangra model, rejected); join
tokens stored in the LCM (rejected - auth is the identity authority).

## R5 - Sealing CA and secret material

**Decision**: Reuse warden/notification's envelope: a 32-byte KEK from file or
env wraps a per-record AES-256-GCM data key; CA private keys, issuer/ACME
account keys, DNS provider credentials, webhook HMAC secrets and any
module-generated workload key are stored sealed, with associated data binding the
record id. Public fields and a `"__set__"` marker are the only things ever
returned. `rotate-kek` re-seals every record in one transaction.
**Rationale**: identical threat (credential at rest) and a proven, 100%-covered
implementation to copy (SR-001).
**Alternatives**: pgcrypto (key in the DB), Vault transit (external dep).

## R6 - Storage and RLS

**Decision**: TimescaleDB, `lcm_app` role without BYPASSRLS, per-call tenant
transaction setting `app.tenant_id`; every table has an RLS policy
`app_tenant_matches`. Audit and certificate history are hypertables. UUIDv7 ids.
Copied from warden/notification `store`.
**Rationale**: proven tenant isolation (SR-005); time-series retention for audit
and issuance history.
**Alternatives**: SQLite (tangra's choice - no RLS, single-writer, rejected);
separate DB per tenant (operationally heavy).

## R7 - Renewal scheduler

**Decision**: An in-service worker pool with a leased SQL claim
(`ClaimDueCertificates ... FOR UPDATE SKIP LOCKED`, lease column) exactly like
the notification scheduler; renews certificates within a window before expiry
(default: the later of 50% of TTL for short SVIDs or N days for long certs);
check interval and worker count configurable. A crash mid-renewal leaves the
lease to expire and the idempotent renew (keyed on the SVID id) completes on the
next claim.
**Rationale**: reuse a proven exactly-once pattern (SC-003); no external
scheduler.
**Alternatives**: cron/external job runner (extra moving part); Valkey-only lock
(the SQL lease is already there and survives Valkey outage).

## R8 - Live distribution

**Decision**: One Valkey stream per tenant (`lcm:events:<tenant>`,
`XADD MAXLEN ~ 10000`) fans certificate events across instances; a module-served
SSE route relayed by the gateway serves the browser (5-minute max age,
`Last-Event-ID` replay within a bounded window, heartbeat), and a `lcm.v1`
server-streaming method serves workload agents. Copied from the notification
stream package.
**Rationale**: identical live-push need; reuse the 100%-covered stream package
(SC-004).
**Alternatives**: long-poll (worse latency); direct push to workloads (needs
inbound connectivity to each workload).

## R9 - Revocation and trust bundle

**Decision**: Revoking a certificate marks it revoked, appends its serial to a
per-tenant revocation list served over the API and as a CRL, and publishes the
revocation to the auth service's revocation feed (the same feed `authclient`
`RevocationChecker` already consumes) so verifiers drop it. The trust bundle
(roots) is served per trust domain; rotation adds the new root, waits a grace
period, then removes the old one.
**Rationale**: integrates with Freya's existing revocation propagation (SR-006)
rather than inventing a second mechanism; standard CA bundle-rotation practice.
**Alternatives**: OCSP responder (heavier; CRL + the existing feed suffice); no
rotation (a CA must be able to rotate its root).

## R10 - Access control

**Decision**: Zanzibar grants copied from warden without folder inheritance:
Owner/Editor/Viewer/Sharer on a certificate or issuer, to a user, role or the
tenant, with expiry; a `use` action (held by owner/editor/sharer and by
`owner`/`admin` roles) gates issuance/enrollment; the default issuer gets an
implicit tenant `use` grant so any member workload can enroll for its own id.
Unreadable resources answer `not_found`.
**Rationale**: reuse the 100%-covered authz package; matches tangra's
CertificatePermissionService semantics (SR-005).
**Alternatives**: RBAC-only (too coarse for per-certificate sharing).

## R11 - Webhooks and events

**Decision**: Outbound webhooks are HMAC-SHA256 signed (per-endpoint sealed
secret), delivered with bounded retries and a scrubbed body (metadata only, no
key material); lifecycle events are also published to the notification module's
`Events` API (when present) and/or the tenant Valkey stream for other modules.
**Rationale**: matches tangra webhooks; reuses `notifyclient` for cross-module
delivery; HMAC is stdlib.
**Alternatives**: unsigned webhooks (rejected - receivers cannot verify origin).

## R12 - DNS providers

**Decision**: Support the ten providers tangra ships (Cloudflare, Route53, Google
Cloud DNS, DigitalOcean, ACME-DNS, PowerDNS, Hurricane Electric, HTTP request,
EasyDNS) plus a generic one, via `lego`'s provider registry; the module exposes
the provider list and the fields each needs, and stores those fields as tenant
secrets.
**Rationale**: `lego` already implements and maintains these; re-implementing DNS
APIs would be large, low-value and error-prone.
**Alternatives**: HTTP-01 only (needs inbound :80 to the workload - impractical);
a smaller provider set (loses parity with tangra).

## R13 - Workload client

**Decision**: Ship `pkg/lcmclient` (a Go client used by modules and by the agent)
and `cmd/lcm-agent` (a CLI/daemon) that enroll, download and auto-renew an SVID
and write it where Freya's file identity provider reads it (`cert.pem`,
`key.pem`, `ca.pem`), so an enrolled workload's Freya `identity.Provider` picks
up rotations. The agent keeps an `lcm.v1` stream open and rotates on `renewed`.
**Rationale**: closes the loop with Freya's identity providers; mirrors tangra's
lcm-client daemon.
**Alternatives**: a SPIFFE Workload API server (a larger surface; out of scope
for v1 - the file provider is what Freya services already use).

## R14 - Backup, statistics, jobs

**Decision**: Backup export/import of issuers, issued-certificate metadata,
permissions and tenant secrets (credentials only on request, audited), bounded
and schema-validated, skip|overwrite - copied from notification's transfer.
Async certificate jobs (queued/processing/completed/failed, cancel/retry) reuse
the same leased-worker pattern as renewal. Statistics are per-tenant SQL
aggregates plus an open-stream count.
**Rationale**: proven patterns already in the codebase.
**Alternatives**: none material.

## STRIDE threat model

Scope: browser ingress (gateway + platform token), service/workload gRPC (SPIFFE
mTLS + policy), outbound ACME/DNS/webhooks, the Valkey event channel, and the
certificate store.

| STRIDE | Threat | Mitigation | Requirement |
|--------|--------|------------|-------------|
| Spoofing | A workload requests an SVID for an identity it is not | Entitlement check: own verified id, `use` grant, or auth-minted token naming the path; no static secret | SR-002, R3, R4 |
| Spoofing | Forged service identity on `lcm.v1` | SPIFFE mTLS + `policy.yaml` allow-list; tenant/actor from the verified id | SR-003, R1 |
| Tampering | Altering a stored certificate/issuer/grant | RLS-scoped writes; append-only audit | SR-005, FR-020 |
| Tampering | Modifying a webhook in transit | HMAC-SHA256 signature per endpoint | R11, FR-015 |
| Repudiation | Denying an issuance/revocation | One audit entry per mutation with actor/subject/outcome, no key material | FR-020, SR-001 |
| Information disclosure | CA/issuer/DNS key or workload key leaking via listing/log/export/event/webhook/error | Envelope sealing; `"__set__"` redaction; credential-free export; scrubbed errors; marker scan in CI | SR-001, R5 |
| Information disclosure | Cross-tenant read of a certificate/secret | RLS + `not_found` for unreadable | SR-005, R6, R10 |
| Denial of service | Oversized CSR/backup/webhook or issuance flood | Size caps (CSR 16 KiB, backup 16 MiB, webhook 64 KiB); per-tenant/per-requester issuance rate limits (Valkey, fail closed) | SR-004 |
| Denial of service | ACME/DNS provider outage stalls the service | Bounded job retries; failures scrubbed and retryable; issuance async | R2, R12, FR-011 |
| Elevation of privilege | Granting a relation above one's own; using an issuer without `use` | Granter-ceiling check; issuance gated by `use`; refusals audited | R10, SR-002 |
| Elevation of privilege | Revoked SVID still trusted | Revocation appended to CRL and published to the auth revocation feed within the propagation window | SR-006, R9 |
