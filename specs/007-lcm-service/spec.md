# Feature Specification: LCM — Certificate & SVID Lifecycle Management

**Feature Branch**: `007-lcm-service`

**Created**: 2026-09-17

**Status**: Draft

**Input**: User description: replicate `/home/jadmin/projects/go-tangra/go-tangra-lcm` as a Freya platform module, replacing tangra's mTLS-client-certificate + static shared-secret authentication with Freya SVID management (the module is itself the platform's SPIFFE certificate authority for the lifecycle of X.509-SVIDs).

## Overview

`lcm` is a tenant-scoped module of the Freya platform that manages the full
lifecycle of X.509 certificates — with SPIFFE X.509-**SVIDs** as the primary
kind — for platform workloads and external clients: **issuance, distribution,
renewal and revocation**, from one or more **issuers** (a self-signed CA
generated per tenant on first use, plus optional ACME/Let's-Encrypt issuers).
It is the production replacement for the throwaway development CA
(`cmd/freya-devca`): where that tool mints static 24-hour SVIDs from files, the
module mints, tracks, renews and revokes them under tenant isolation, access
control and audit.

The tangra service authenticated clients with generic mTLS client certificates
plus a per-tenant static shared secret. **That whole mechanism is removed.** In
Freya, callers reach the module the same way every other module is reached:
service-to-service over the platform's existing SPIFFE mTLS, and the browser
API through the application gateway with a platform token. A workload
**enrolls** for an SVID using its own Freya platform identity or a short-lived
enrollment token minted by the auth service — never a static secret.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Issue and manage a certificate/SVID (Priority: P1)

An administrator (or an authorised workload) obtains an X.509-SVID for a SPIFFE
identity and manages it through its life. On first use the module generates a
self-signed root/intermediate CA for the tenant's trust domain. The requester
submits a certificate signing request (CSR) for a SPIFFE ID
(`spiffe://<trust-domain>/<path>`) with a validity and optional DNS/URI SANs, or
asks the module to generate the key pair. The module verifies the requester is
entitled to that identity, mints the certificate from the default (or chosen)
issuer, records an **issued-certificate** entry, and returns the certificate,
its chain and the trust bundle (and, only when the module generated it, the
private key — once). The administrator can list, inspect, renew, force-renew,
revoke, delete and re-download issued certificates.

**Why this priority**: Issuing and managing certificates is the reason the
service exists; nothing else has value without it. It is the minimum viable
product and can ship alone.

**Independent Test**: With only US1, an operator creates a tenant, the CA is
auto-generated, they issue a certificate for a SPIFFE ID, download the
cert + chain + bundle, verify the chain against the bundle, renew it, revoke it,
and confirm the private key and CA key never appear in any listing, export or
log.

**Acceptance Scenarios**:

1. **Given** a tenant with no issuer, **When** the first certificate is
   requested, **Then** a self-signed CA for the tenant's trust domain is
   generated, stored with its private key encrypted, and used to sign the
   certificate.
2. **Given** a CSR for `spiffe://<td>/workload/api`, **When** an entitled
   requester issues it, **Then** an issued-certificate record is created (serial,
   SPIFFE id/subject, issuer, not-before/after, status `active`, fingerprint,
   SANs, owner) and the certificate + chain + bundle are returned.
3. **Given** an issued certificate, **When** it is downloaded, **Then** the
   response never contains a private key unless the module generated the key
   pair, in which case the key is returned exactly once and is sealed at rest.
4. **Given** an active certificate, **When** it is renewed, **Then** a new
   certificate with the same SPIFFE id and a fresh validity is issued and the
   previous one is superseded; **When** it is revoked, **Then** its status
   becomes `revoked` and it is added to the revocation list.
5. **Given** any listing, export-without-credentials or log, **Then** no CA
   private key, issuer credential or workload private key appears in it.

---

### User Story 2 - Control who may issue, read and revoke (Priority: P2)

Because a certificate authority is a high-value target, access to certificates
and issuers is fine-grained. An owner of a certificate or issuer grants other
users, roles, or the whole tenant an **owner / editor / viewer / sharer**
relation (with optional expiry); the relation decides who may read, issue
(the "use" action), renew, revoke, deploy or delete. The API can grant, revoke,
list, check and return effective permissions, and list the certificates a
subject can access.

**Why this priority**: Once certificates exist, limiting who can mint or revoke
them is the primary security control. It builds directly on US1.

**Independent Test**: An owner grants a viewer read-only access and an editor
issue/renew access to a certificate; the viewer can download but not renew, the
editor can renew but not delete, a user with no grant sees `not_found`, and
every grant and refusal is audited.

**Acceptance Scenarios**:

1. **Given** a certificate owned by user A, **When** A grants user B the viewer
   relation, **Then** B can read and download it but cannot issue, renew, revoke
   or deploy it.
2. **Given** an issuer, **When** a subject holds the "use"/issue action through a
   grant, **Then** they may mint certificates from that issuer; otherwise
   issuance is refused.
3. **Given** a certificate the caller may not read, **When** they request it by
   id, **Then** the response is `not_found`, never `forbidden`, so existence is
   not disclosed.
4. **Given** a granter, **When** they try to grant a relation stronger than
   their own, **Then** the request is refused and audited.

---

### User Story 3 - Enroll a workload and keep its SVID fresh (Priority: P3)

This is the Freya replacement for tangra's shared-secret client registration. A
workload (or its agent) enrolls for an SVID using its Freya platform identity or
a short-lived enrollment token minted by the auth service. Enrollment may be
**auto-approved** (puppet-style automatic signing) or **manually approved**
through a certificate-request workflow. Each request is tracked as an async
**job** (queued → processing → completed/failed) the caller can poll, cancel or
retry. Once issued, the workload keeps its SVID fresh: an automated **renewal
scheduler** renews certificates before expiry, and a **live distribution
stream** (server-sent events through the gateway for the browser; a streaming
method for workload agents) pushes `issued`/`renewed`/`revoked` events so the
workload rotates with no downtime. Workloads report the certificate they
installed and can list their installed certificates.

**Why this priority**: This is the differentiator versus tangra — SVID
management with no static secret — and it makes issued certificates usable at
scale. It depends on US1 (issuance) and benefits from US2 (access).

**Independent Test**: A workload with a Freya identity enrolls (auto-approve on),
receives an SVID, keeps an open stream, and — after the clock is advanced past
the renewal window — receives a `renewed` event with a fresh SVID without
re-enrolling; with auto-approve off, the same request stays `pending` until an
administrator approves it.

**Acceptance Scenarios**:

1. **Given** auto-approve enabled, **When** an entitled workload enrolls, **Then**
   an SVID is issued automatically and the enrollment job completes; **Given**
   auto-approve disabled, **Then** a certificate request is created `pending` and
   no certificate is issued until it is approved.
2. **Given** a `pending` request, **When** an administrator approves it, **Then**
   the certificate is issued and the job completes; **When** it is rejected,
   **Then** the request is `rejected` and no certificate is issued.
3. **Given** a certificate within its renewal window, **When** the scheduler
   runs, **Then** it is renewed exactly once even if several instances run
   concurrently, and a `renewed` event is delivered to the workload's stream.
4. **Given** an open distribution stream and a reconnect with the last event id,
   **Then** events published during the gap are replayed; beyond the replay
   window the client is told to re-sync.
5. **Given** a static shared secret, **Then** no endpoint accepts it — enrollment
   requires a platform identity or an auth-minted enrollment token.

---

### User Story 4 - ACME issuers, external notifications and credentials (Priority: P4)

For certificates that must be publicly trusted, an administrator adds an
**ACME/Let's-Encrypt** issuer that solves DNS-01 challenges through a configured
DNS provider (Cloudflare, AWS Route53, Google Cloud DNS, DigitalOcean, ACME-DNS,
PowerDNS, Hurricane Electric, HTTP request, EasyDNS, or a generic one). The
credentials those issuers need (ACME account keys, DNS provider API tokens) are
kept as per-tenant **tenant secrets**, encrypted at rest and never returned in
full. Lifecycle changes publish **events** to other modules (through the
notification module) and deliver HMAC-signed **webhooks** to external systems
for configured event types with retries. An operator can **deploy** an issued
certificate to a target and list deployment targets.

**Why this priority**: These extend the module to publicly-trusted certificates
and external integrations. They are valuable but not required for the internal
SVID use case, so they follow the core.

**Independent Test**: An administrator stores a DNS provider credential as a
tenant secret, creates an ACME issuer that references it, and issues a
certificate whose challenge is solved via DNS-01 (against a mock provider); a
configured webhook receives an HMAC-signed `certificate.issued` callback and the
secret value never appears in any response, event, webhook body or log.

**Acceptance Scenarios**:

1. **Given** a DNS provider credential stored as a tenant secret, **When** an
   ACME issuer references it and a certificate is requested, **Then** the DNS-01
   challenge is solved and a certificate is issued; the credential is never
   returned in full (write-only, shown as a redaction marker).
2. **Given** a webhook endpoint configured for `certificate.issued`, **When** a
   certificate is issued, **Then** the endpoint receives an HMAC-signed callback,
   with retries on failure, and no secret material in the body.
3. **Given** an issued certificate and a deployment target, **When** an operator
   deploys it, **Then** the deployment is recorded and other modules receive a
   lifecycle event.
4. **Given** a tenant secret, **When** it is rotated, **Then** issuers using it
   continue to work with the new value and the rotation is audited.

---

### User Story 5 - Operate, audit and recover (Priority: P5)

An operator observes and maintains the certificate authority. Every operation
(issued, approved, rejected, renewed, revoked, deployed, secret rotated, granted,
backup exported) leaves an **append-only, tamper-evident audit** entry that never
records key material. The module serves the **trust bundle** for each trust
domain (so workloads validate peers) and a **revocation list**, and publishes
revocations so verifiers drop revoked identities. **Statistics** report per-tenant
and system-wide counts (certificates by status, issuers, jobs, clients,
certificates expiring soon, recent errors). A **backup** exports issuers,
issued-certificate metadata, permissions and tenant secrets (credentials only on
explicit request) and imports them with skip-or-overwrite for duplicates.

**Why this priority**: Auditability, trust-bundle/revocation distribution,
statistics and backup are essential to run a CA in production, but layer on top
of the core lifecycle.

**Independent Test**: An operator issues and revokes a certificate, confirms both
appear in the audit trail with no key material, fetches the trust bundle and
revocation list, sees the statistics reflect the change, exports a backup without
credentials (no secret in the file), and re-imports it into a second tenant with
skip then overwrite.

**Acceptance Scenarios**:

1. **Given** any mutating operation, **Then** exactly one audit entry is written
   with the actor, subject and outcome and no private key, credential or CSR key
   material.
2. **Given** a revoked certificate, **When** the revocation list and the identity
   revocation feed are read, **Then** the certificate's serial appears and
   verifiers drop it.
3. **Given** a trust domain, **When** the trust bundle is requested, **Then** the
   current roots are returned and a bundle rotation adds the new root before the
   old one is removed.
4. **Given** a backup exported without credentials, **When** it is inspected,
   **Then** it contains issuer and certificate metadata but no CA key, private
   key or tenant-secret value; **When** exported with credentials, the export is
   audited as a bulk disclosure.

---

### Edge Cases

- **CA/issuer key compromise or loss**: the CA and issuer private keys are
  encrypted with a key-encryption key held outside the database; losing the KEK
  makes them unrecoverable. Rotating the KEK re-seals every stored key.
- **Concurrent renewal**: several service instances must renew a due certificate
  exactly once (a lease claim) — no duplicate issuance.
- **Enrollment for an identity the requester is not entitled to**: refused; a
  workload may only obtain an SVID for a SPIFFE path it is authorised for.
- **CSR mismatch**: a CSR whose public key, requested SANs or SPIFFE id conflicts
  with policy is rejected with a specific reason.
- **Clock skew / already-expired request**: a validity in the past or beyond the
  issuer's ceiling is clamped or refused.
- **Oversized CSR / backup / webhook payload**: bounded and refused above the
  limit.
- **ACME/DNS provider outage**: the job fails with a scrubbed reason and is
  retryable; no credential leaks in the error.
- **Revocation of an in-use SVID**: the workload's stream receives a `revoked`
  event and must re-enroll; the revocation is distributed immediately.
- **Cross-tenant access**: a certificate, issuer or secret of one tenant is
  invisible to another (answers `not_found`).

## Requirements *(mandatory)*

### Functional Requirements

**Issuers & CA**

- **FR-001**: The system MUST generate a self-signed root/intermediate CA for a
  tenant's trust domain on first use and store its private key encrypted at rest,
  never returning it.
- **FR-002**: The system MUST let administrators create, read, update and delete
  issuers of type self-signed and ACME, with exactly one default issuer per trust
  domain, and MUST list the available DNS-01 providers and the fields each
  requires.
- **FR-003**: The system MUST store every issuer, ACME account and DNS-provider
  credential encrypted at rest and never return it in full (redacted marker;
  write-only update semantics).

**Issuance & certificates**

- **FR-004**: Users and workloads MUST be able to request an X.509 certificate
  for a SPIFFE id by submitting a CSR, or by asking the system to generate the
  key pair, with a validity and optional DNS/URI SANs.
- **FR-005**: The system MUST verify the requester is entitled to the requested
  SPIFFE identity and issuer before issuing, and MUST clamp or refuse a validity
  beyond the issuer's ceiling.
- **FR-006**: The system MUST record an issued-certificate entry (serial, SPIFFE
  id/subject, issuer, not-before/after, status, fingerprint, SANs, owner, tenant,
  creator/updater, timestamps) for every certificate.
- **FR-007**: Users MUST be able to list, get, update metadata, renew,
  force-renew, revoke, delete and download issued certificates; a download MUST
  return the certificate, its chain and the trust bundle, and MUST return a
  private key only when the system generated it, exactly once.
- **FR-008**: The system MUST expose the status of a certificate as one of
  `active`, `expiring`, `expired` or `revoked`, deriving `expiring`/`expired`
  from the validity window.

**Enrollment, requests & jobs**

- **FR-009**: The system MUST allow a workload to enroll using its Freya platform
  identity or a short-lived enrollment token minted by the auth service, and MUST
  NOT accept any static shared secret for authentication or enrollment.
- **FR-010**: The system MUST support auto-approve (automatic signing) and a
  manual approval workflow: certificate requests with create, list, get, approve
  and reject and a status of `pending`, `approved`, `rejected` or `issued`.
- **FR-011**: The system MUST track each request as an async job with a status of
  `queued`, `processing`, `completed` or `failed`, and let the caller get status,
  get result, list, cancel and retry it.

**Renewal & distribution**

- **FR-012**: The system MUST automatically renew certificates within a
  configurable window before expiry using a distributed scheduler that renews
  each due certificate exactly once regardless of the number of instances.
- **FR-013**: The system MUST deliver live certificate-update events
  (`issued`, `renewed`, `revoked`) to a per-user browser stream and to a workload
  agent stream, with reconnection, heartbeat and replay from a last event id
  within a bounded window.
- **FR-014**: Workloads MUST be able to report the certificate they installed and
  list their installed certificates; operators MUST be able to deploy an issued
  certificate to a target and list deployment targets.

**Integrations**

- **FR-015**: The system MUST publish lifecycle events
  (`certificate.issued/renewed/revoked/failed`) for other modules and MUST
  deliver HMAC-signed webhooks to configured endpoints for selected event types,
  with retries, containing no secret material.
- **FR-016**: The system MUST support ACME/Let's-Encrypt issuance solving DNS-01
  challenges through the configured DNS provider using credentials drawn from
  tenant secrets.
- **FR-017**: Administrators MUST be able to create, list, get, update, delete and
  rotate per-tenant secrets used by issuers and DNS providers, never seeing a
  stored secret value in full.

**Access, trust & revocation**

- **FR-018**: Access to certificates and issuers MUST be governed by owner,
  editor, viewer and sharer relations granted to users, roles or the tenant with
  optional expiry, with grant, revoke, list, check, effective, list-accessible
  and list-all operations, and the "use"/issue action MUST gate enrollment and
  issuance.
- **FR-019**: The system MUST serve the current trust bundle for each trust
  domain and support bundle rotation (add the new root before removing the old),
  and MUST serve a revocation list and publish revocations to the platform
  identity revocation feed.

**Operations**

- **FR-020**: The system MUST write an append-only, tamper-evident audit entry for
  every mutating operation (issued, approved, rejected, renewed, revoked,
  deployed, secret rotated, granted/revoked, backup exported), recording the
  actor, subject and outcome and no key material or secret.
- **FR-021**: The system MUST report per-tenant and system-wide statistics:
  certificates by status, issuers, jobs, clients, certificates expiring soon and
  recent errors.
- **FR-022**: The system MUST export a tenant backup of issuers, issued-certificate
  metadata, permissions and tenant secrets (secret values only on explicit
  request, audited as a bulk disclosure) and import it with skip or overwrite for
  duplicates.

**Platform integration**

- **FR-023**: The module MUST register with the application gateway (routes and
  API permissions such as `certificates:read/manage/issue/revoke`,
  `issuers:read/manage`, `enrollment:enroll`, `jobs:read/manage`,
  `permissions:manage`, `secrets:manage`, `backup:manage`, `stats:read`, plus
  CASL abilities) and MUST source user identity, tenant, roles and display names
  from the auth service.
- **FR-024**: The module MUST expose service-to-service methods (not proxied by
  the gateway) for module-to-module SVID issuance, renewal and verification and
  for event publishing, and MUST ship a browser UI as a Module Federation remote
  (dashboard, issuers, certificates/issued-certificates, certificate
  requests/jobs, permissions, tenant secrets, audit log) composed by the shell.
- **FR-025**: The system MUST ship a workload client that enrolls, downloads and
  auto-renews an SVID and integrates with the platform's file/workload identity
  provider.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: public browser ingress through the application
  gateway (platform token); service-to-service gRPC over SPIFFE mTLS; outbound to
  ACME servers, DNS providers and webhook endpoints; a message/event channel to
  other modules.
- **Data classification**: **credentials and key material** (CA private keys,
  issuer/ACME/DNS credentials, workload private keys when generated), certificate
  metadata (internal), tenant/user identifiers.
- **Authentication/Authorization**: browser callers via the gateway platform
  token verified with the auth service; workloads and modules via SPIFFE mTLS and
  the module's own SPIFFE policy allow-list; per-object Zanzibar relations;
  enrollment via platform identity or a short-lived auth-minted token — never a
  static secret.
- **Threat scenarios**: theft of a CA/issuer key from the database, an export or a
  log; issuance of an SVID for an identity the requester is not entitled to
  (privilege escalation / impersonation); replay of an enrollment token; forged
  service identity on the gRPC API; credential leakage through events, webhooks or
  errors; unbounded CSR/backup/webhook payloads (DoS); cross-tenant read/write;
  revoked-but-still-trusted SVIDs.
- **SR-001**: The system MUST store all CA, issuer, ACME, DNS-provider and
  service-generated private keys sealed with envelope encryption and MUST never
  return them in any response, export-without-credentials, event, webhook body or
  log.
- **SR-002**: The system MUST refuse to issue an SVID for a SPIFFE identity the
  requester is not entitled to, and MUST reject any static shared secret.
- **SR-003**: The system MUST verify the SPIFFE service identity of every
  module-to-module call against a policy allow-list and derive the tenant and
  actor from the verified identity and the request.
- **SR-004**: The system MUST bound CSR, backup and webhook payload sizes and
  refuse anything above the limit, and MUST scrub credentials from every error,
  event and webhook.
- **SR-005**: The system MUST answer `not_found` (never `forbidden`) for a
  certificate, issuer or secret the caller may not read, so existence is not
  disclosed across tenants or access boundaries.
- **SR-006**: The system MUST distribute a revocation within the platform's
  revocation propagation window so verifiers drop a revoked SVID.

### Key Entities *(include if feature involves data)*

- **Issuer**: a signing authority for a trust domain — self-signed (owns a CA
  key) or ACME (owns an account and references a DNS provider). Has a type, a
  default flag, sealed credentials, owner/tenant and timestamps.
- **CA / Trust bundle**: the root/intermediate material for a tenant's trust
  domain and the set of roots workloads use to validate peers; supports rotation.
- **Certificate request**: a pending, approved, rejected or issued application for
  a certificate, carrying the requested SPIFFE id, SANs, validity, CSR (if any)
  and approver.
- **Certificate job**: the async execution of a request — queued, processing,
  completed or failed — with a result reference and retry count.
- **Issued certificate**: a minted X.509 certificate — serial, SPIFFE id/subject,
  issuer, validity window, status, fingerprint, SANs, owner/tenant,
  creator/updater, timestamps; the private key is stored only when the module
  generated it, sealed.
- **Installed certificate / deployment target**: what a workload reports as
  installed, and a destination an operator can deploy a certificate to.
- **Tenant secret**: a per-tenant credential (ACME account key, DNS provider
  token) used by issuers, sealed and write-only.
- **Grant**: a Zanzibar relation (owner/editor/viewer/sharer) on a certificate or
  issuer for a user, role or the tenant, with optional expiry.
- **Webhook endpoint**: an external URL, the event types it subscribes to and its
  HMAC signing secret (sealed).
- **Audit entry**: an append-only record of one operation — actor, subject,
  outcome, correlation — with no key material.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An administrator can obtain a working certificate for a SPIFFE
  identity — from an empty tenant through CA auto-generation to a downloaded
  cert + chain + bundle that validates — in under 3 minutes, with no manual key
  handling.
- **SC-002**: 100% of CA keys, issuer/ACME/DNS credentials, tenant-secret values
  and workload private keys are absent from every listing, credential-free export,
  event, webhook body and captured log (verified by an automated material scan).
- **SC-003**: A workload keeps a valid SVID indefinitely without re-enrolling:
  after enrollment, automated renewal delivers a fresh SVID before expiry in at
  least 99% of renewal cycles, and never issues a duplicate for a single due
  certificate.
- **SC-004**: A live certificate-update event reaches an open workload/browser
  stream within 2 seconds of issuance, renewal or revocation.
- **SC-005**: An entitlement matrix holds without exception: a viewer can read but
  not issue/renew/revoke, an issuer-granted subject can mint, an ungranted or
  cross-tenant caller receives `not_found`, and every grant and refusal is
  audited.
- **SC-006**: A revoked SVID is rejected by verifiers within the platform's
  revocation propagation window (target under 10 seconds in the development
  stack), and its serial appears in the revocation list.
- **SC-007**: Every mutating operation produces exactly one audit entry with no
  key material, and a with-credentials backup export is recorded as a bulk
  disclosure.
- **SC-008**: A 100-certificate tenant backup round-trips (export then import into
  a second tenant) in under 10 seconds, and importing again with skip changes
  nothing.

## Assumptions

- The Freya framework, its SPIFFE identity/mTLS, service-policy allow-list, audit
  and observability are reused; the module does not re-implement transport
  security.
- Storage is TimescaleDB with per-tenant row-level security; there is no SQLite
  (unlike tangra).
- A key-encryption key is provided out of band (file or environment) to seal CA,
  issuer and secret material, mirroring the warden/notification modules.
- The auth service is the source of user identity, tenant, roles, display names,
  the platform token verification keys/revocation feed and short-lived enrollment
  tokens; the gateway forwards browser traffic and enforces per-route API
  permissions; the notification module (when present) relays lifecycle events and
  can notify operators.
- SPIFFE X.509-SVIDs are the primary certificate kind; general TLS server/client
  certificates (including ACME/publicly-trusted ones) are supported through the
  same issuance pipeline.
- ACME and DNS provider interactions run against real external services in
  production and mock/staging providers in tests; ten DNS providers are supported,
  matching tangra, with a generic provider for the rest.
- The workload client and optional CLI/daemon are delivered as a Go package
  (and binary) for workloads to enroll and auto-renew; the browser UI follows the
  platform's Materio design and is composed by the shell.
- Multi-instance deployment is supported; renewal and event distribution are
  coordinated so work is not duplicated.
