# Data Model: LCM — Certificate & SVID Lifecycle Management

TimescaleDB, database `lcm`, application role `lcm_app` (no BYPASSRLS). Every
table carries `tenant_id uuid not null` and an RLS policy `app_tenant_matches`
using `current_setting('app.tenant_id')`, set per transaction (copied from
warden/notification `store`). Ids are UUIDv7. `created_by`/`updated_by` hold the
actor (user id or service SPIFFE id). Timestamps are `timestamptz`. Private and
credential material is stored only in the `*_sealed` columns (envelope
encryption, R5) and never selected into a view.

## Tables

### issuers
The signing authorities of a tenant.
- `id`, `tenant_id`, `name` (unique per tenant, case-insensitive)
- `type` - `self_signed` | `acme`
- `trust_domain` - the SPIFFE trust domain this issuer signs for
- `is_default bool` - exactly one default per (tenant, trust_domain), partial unique index
- `ca_id` (nullable) - for self-signed: the CA whose key signs
- `acme_directory_url`, `acme_email`, `dns_provider` (for ACME)
- `settings_public jsonb` - non-secret config (ceilings, key type, ACME contact)
- `settings_sealed bytea` - sealed ACME account key / DNS credentials reference
- `enabled bool`, `created_by`, `updated_by`, `created_at`, `updated_at`

### cas
Root/intermediate material per trust domain, with rotation.
- `id`, `tenant_id`, `trust_domain`
- `cert_pem` (public root/intermediate chain), `key_sealed bytea` (private key)
- `state` - `active` | `next` | `retiring` (bundle rotation, R9)
- `not_before`, `not_after`, `serial`, `created_at`
- Index: `(tenant_id, trust_domain, state)`

### certificate_requests
A pending/approved/rejected/issued application for a certificate.
- `id`, `tenant_id`, `issuer_id`, `spiffe_id`, `sans jsonb`, `key_type`
- `csr_pem` (nullable - present when the requester supplied a CSR)
- `validity_seconds`, `requested_by`, `requester_kind` (`user`|`service`|`token`)
- `status` - `pending` | `approved` | `rejected` | `issued`
- `approver` (nullable), `reason` (nullable, scrubbed), timestamps
- Index: `(tenant_id, status, created_at)`

### certificate_jobs
Async execution of a request.
- `id`, `tenant_id`, `request_id`, `type` (`issue`|`renew`|`acme`)
- `status` - `queued` | `processing` | `completed` | `failed`
- `lease_until` (nullable - worker lease), `attempts int`, `max_attempts int`
- `result_certificate_id` (nullable), `error` (nullable, scrubbed)
- `run_after timestamptz`, timestamps
- Index: `(tenant_id, status, run_after)`; claim uses `FOR UPDATE SKIP LOCKED`

### issued_certificates
A minted certificate/SVID.
- `id`, `tenant_id`, `issuer_id`, `request_id` (nullable)
- `serial` (unique per tenant), `spiffe_id`, `subject`, `sans jsonb`
- `not_before`, `not_after`, `fingerprint_sha256`
- `status` - `active` | `expiring` | `expired` | `revoked` (expiring/expired derived from `not_after`)
- `cert_pem`, `chain_pem`
- `key_sealed bytea` (nullable - only when the module generated the key), `key_delivered bool`
- `superseded_by` (nullable - set on renewal), `owner`, `created_by`, `updated_by`, timestamps
- Indexes: `(tenant_id, status, not_after)` (renewal scan), `(tenant_id, spiffe_id)`, `(tenant_id, serial)`

### revocations
- `id`, `tenant_id`, `certificate_id`, `serial`, `reason` (RFC 5280 code), `revoked_at`, `revoked_by`
- Index: `(tenant_id, revoked_at)` - feeds the CRL and the identity revocation feed

### installed_certificates
What a workload reports as installed.
- `id`, `tenant_id`, `certificate_id`, `client_id` (workload SPIFFE id), `installed_at`, `reported_at`

### deployment_targets
A destination an operator can deploy a certificate to.
- `id`, `tenant_id`, `name`, `kind` (`file`|`pull`|`webhook`), `config_public jsonb`, `config_sealed bytea` (credentials), timestamps

### tenant_secrets
Per-tenant credentials used by issuers/DNS providers.
- `id`, `tenant_id`, `name` (unique per tenant), `kind` (`acme_account`|`dns_credential`)
- `value_sealed bytea` (write-only; API shows `"__set__"`), `created_by`, `updated_by`, timestamps

### webhook_endpoints
- `id`, `tenant_id`, `name`, `url`, `event_types text[]`, `secret_sealed bytea` (HMAC key), `enabled bool`, timestamps

### grants
Zanzibar relations on a certificate or issuer (copied from warden, no ancestors).
- `id`, `tenant_id`, `resource_type` (`certificate`|`issuer`), `resource_id`
- `subject_type` (`user`|`role`|`tenant`), `subject_id`, `relation` (`owner`|`editor`|`viewer`|`sharer`)
- `granted_by`, `granted_at`, `expires_at` (nullable)
- Unique `(tenant_id, resource_type, resource_id, subject_type, subject_id)`

### lcm_certificate_log (hypertable)
Issuance/renewal history for statistics and audit joins.
- `ts`, `tenant_id`, `certificate_id`, `event` (`issued`|`renewed`|`revoked`|`failed`), `issuer_id`, `spiffe_id`, `error` (scrubbed)

### lcm_audit_events (hypertable)
Append-only audit; the `lcm_app` role may INSERT and SELECT only (no UPDATE/DELETE).
- `ts`, `tenant_id`, `event_type` (closed vocabulary), `actor_kind` (`user`|`service`|`system`), `actor_id`
- `subject_kind` (`certificate`|`issuer`|`request`|`job`|`secret`|`grant`|`webhook`|`bundle`|`backup`|`system`)
- `subject_id`, `subject_name`, `outcome` (`ok`|`refused`|`failed`), `reason`, `correlation_id`, `details jsonb` (guarded: no key material or secret)

## Audit vocabulary (closed)

`issuer_created/updated/deleted`, `ca_generated`, `bundle_rotated`,
`certificate_requested`, `request_approved/rejected`,
`certificate_issued/renewed/revoked/deleted`, `certificate_deployed`,
`certificate_installed`, `secret_created/updated/rotated/deleted`,
`webhook_created/updated/deleted`, `grant_created/revoked`, `access_refused`,
`backup_exported`, `backup_exported_with_credentials`, `backup_imported`,
`stream_opened`, `stream_refused`, `enrollment_issued`, `enrollment_refused`.

Detail guard drops any key containing `key`, `secret`, `token`, `password`,
`private`, `csr`; strings truncated to 256 chars.

## State machines

**Certificate request**: `pending` -> `approved` -> `issued`; `pending` ->
`rejected`. Auto-approve collapses `pending`->`approved` on creation.

**Certificate job**: `queued` -> `processing` -> `completed` | `failed`;
`failed` -> `queued` (retry, until `max_attempts`); `queued`/`processing` ->
`failed` (cancel).

**Issued certificate**: `active` -> `expiring` (within the window) -> `expired`
(past `not_after`) - the first two are derived on read; `active`/`expiring` ->
`revoked` (explicit); renewal creates a new `active` certificate and sets
`superseded_by` on the old one.

**CA / bundle**: `active`; rotation issues a `next` root, promotes it to
`active` (old -> `retiring`), then removes `retiring` after the grace period.

## Validation rules (from requirements)

- Issuer name 1-100 chars, unique per tenant; exactly one default per trust
  domain (FR-002).
- SPIFFE id matches `spiffe://<trust-domain>/<path>`; trust domain matches the
  issuer's; path validated against the requester's entitlement (FR-005, R3).
- CSR <= 16 KiB, parses, public key >= 256-bit ECDSA / Ed25519, its SANs subset
  of the requested SANs (FR-004, SR-004).
- Validity 1 minute .. issuer ceiling; a past `not_before` is clamped to now
  (FR-005, edge cases).
- Tenant-secret value and webhook secret are write-only; responses show
  `"__set__"` (FR-003, FR-017, SR-001).
- Backup <= 16 MiB, schema-validated, bounded item counts; mode `skip`|`overwrite`
  (FR-022).
