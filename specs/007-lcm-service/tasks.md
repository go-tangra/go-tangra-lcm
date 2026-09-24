---
description: "Task list for LCM — Certificate & SVID Lifecycle Management"
---

# Tasks: LCM — Certificate & SVID Lifecycle Management

**Input**: Design documents from `/specs/007-lcm-service/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: MANDATORY (Constitution Principle IV, NON-NEGOTIABLE). Every user story lists
its test tasks before implementation; tests are written and confirmed failing first. Every
story here touches auth, transport, parsing, crypto or secrets, so each includes negative
security tests, and the parsing/crypto boundaries add fuzz tests.

**Organization**: grouped by user story (P1–P5) so each is independently implementable and testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no incomplete dependencies)
- **[Story]**: US1–US5; Setup/Foundational/Polish carry no story label
- Paths are repository-relative under `services/lcm/` unless noted.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: scaffold the module with the same shape as `services/notification`.

- [X] T001 Create the `services/lcm/` tree (api/{openapi,proto/lcm/v1,schema}, cmd/{lcmsvc,lcm-agent}, deploy/, internal/, pkg/{lcmmanifest,lcmclient}, ui/, tests/{contract,integration,fuzz}, docs/) per plan.md Project Structure
- [X] T002 Add the module to the Go workspace/build (go.mod or workspace entry, module path `.../services/lcm`) and wire it into the repo build/lint targets
- [X] T003 [P] Copy `services/lcm/api/openapi/lcm-api.openapi.yaml` from `specs/007-lcm-service/contracts/lcm-api.openapi.yaml` and add the `//go:embed` loader in `api/openapi/openapi.go`
- [X] T004 [P] Copy `services/lcm/api/proto/lcm/v1/lcm.v1.proto` from `specs/007-lcm-service/contracts/lcm.v1.proto`, add the `buf`/`protoc` generate step, and generate `lcmv1` stubs
- [X] T005 [P] Copy `services/lcm/api/schema/backup.schema.json` from `specs/007-lcm-service/contracts/backup.schema.json` and embed it
- [X] T006 [P] Create `deploy/` files: `compose.yaml` (TimescaleDB, Valkey, mock-ACME/Pebble, mock-DNS), `dev.yaml`, `policy.yaml` (SPIFFE allow-list skeleton), `kek.dev`, `init-db.sql` placeholder
- [X] T007 [P] Configure lint/format/vet for the module and add `gosec`/`govulncheck` targets matching the other services

**Checkpoint**: module skeleton compiles empty; contracts embedded.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: infrastructure every user story needs. ⚠️ No story work begins until this phase is done.

- [X] T008 [P] Implement `internal/config` (service config: DB DSN, Valkey, KEK, gateway/auth endpoints, renewal window/interval/workers, payload/stream limits) loading `deploy/dev.yaml`
- [X] T009 Write `deploy/init-db.sql` + goose migrations for all tables (issuers, cas, certificate_requests, certificate_jobs, issued_certificates, revocations, installed_certificates, deployment_targets, tenant_secrets, grants, webhook_endpoints, lcm_audit_events + lcm_certificate_log hypertables), the `lcm_app` role and per-tenant RLS policies (`app.tenant_id`) per data-model.md
- [X] T010 [P] Implement `internal/store` (pgx pool, per-request tenant RLS via `SET LOCAL app.tenant_id`, transaction helper) mirroring `services/notification/internal/store`
- [X] T011 [P] Define `internal/repo` Store interfaces and row types for every entity in data-model.md
- [X] T012 Implement `internal/repo/repodb` (SQL implementation of the repo interfaces over `internal/store`)
- [X] T013 [P] Implement `internal/memstore` (in-memory repo double used by unit tests and the fake clock)
- [X] T014 [P] Unit test `internal/sealed` (envelope encrypt/decrypt, KEK rotation, tamper/`__set__` redaction) — write FIRST, must fail
- [X] T015 Implement `internal/sealed` envelope encryption (AES-GCM DEK sealed by KEK, `rotate-kek`), 100% coverage target
- [X] T016 [P] Fuzz test `internal/csr` (CSR PEM parser) and the SPIFFE-id validator in `tests/fuzz` — write FIRST
- [X] T017 Implement `internal/csr` (CSR parse/validate, SPIFFE-id parse/validate, PEM/bundle encode) with bounded input sizes
- [X] T018 [P] Unit test `internal/authz` entitlement/relation resolution (owner/editor/viewer/sharer, `use`, above-granter, tenant grants) — write FIRST
- [X] T019 Implement `internal/authz` (Zanzibar relation resolver + `use`/issue entitlement + `ErrAboveGranter`) over the grants repo
- [X] T020 [P] Implement `internal/audit` (closed-vocabulary batched append to `lcm_audit_events`, no key material) per data-model.md audit vocabulary
- [X] T021 [P] Implement the shared HTTP error mapper (`internal/httpapi` errors.go): closed reason vocabulary, `not_found` masking for unreadable objects (SR-005), 413/422/429 mapping
- [X] T022 Implement `internal/httpapi` server skeleton: kin-openapi request validation middleware, platform-token verification via `authclient`, CSRF, body-size + timeout enforcement from the OpenAPI extensions
- [X] T023 Implement `internal/grpcapi` server skeleton: SPIFFE mTLS listener, policy allow-list check (SR-003), tenant/actor derivation from the verified identity
- [X] T024 Implement `internal/app` wiring (construct repos, services, servers) and `cmd/lcmsvc/main.go` (bootstrap, `rotate-kek` subcommand)
- [X] T025 [P] Implement `pkg/lcmmanifest` (prefixes `/api/lcm`; permissions certificates:read/manage/issue/revoke, issuers:read/manage, enrollment:enroll, jobs:read/manage, permissions:manage, secrets:manage, backup:manage, stats:read; CASL abilities; body/timeout limits) from `contracts/manifest.md`
- [X] T026 Wire gateway registration via `gatewayclient` in `internal/app` and finalize `deploy/policy.yaml` (do NOT own the shared `/ui` prefix; remote served via `/m/lcm/`)

**Checkpoint**: service starts, registers with the gateway, authenticates browser + mTLS callers, empty stores wired.

---

## Phase 3: User Story 1 — Issue and manage a certificate/SVID (Priority: P1) 🎯 MVP

**Goal**: from an empty tenant, auto-generate the CA, create issuers, mint an X.509-SVID from a CSR or generated key, and list/get/update/renew/revoke/delete/download issued certificates.

**Independent Test**: an operator creates a tenant, the CA auto-generates on first use, they issue an SVID for a SPIFFE id and download cert + chain + bundle that validates; renew and revoke change status.

### Tests for User Story 1 (write FIRST, confirm failing) ⚠️

- [X] T027 [P] [US1] Contract test: OpenAPI issuer + certificate paths ↔ registered routes in `tests/contract/openapi_test.go`
- [X] T028 [P] [US1] Contract test: `pkg/lcmmanifest` prefixes/permissions in `tests/contract/manifest_test.go`
- [X] T029 [P] [US1] Unit test `internal/ca` (self-signed root/intermediate generation, sealed key, bundle assembly) with fake clock — must fail
- [X] T030 [P] [US1] Unit test `internal/issue` (mint from CSR; generate key path returns key once; validity/SAN enforcement; SR-002 entitlement refusal) — must fail
- [X] T031 [P] [US1] Negative security test: issuance refuses a SPIFFE id the requester is not entitled to, rejects a static shared secret, and never returns a CA/issuer key (SR-001/SR-002) in `tests/integration`
- [X] T032 [P] [US1] Fuzz test: PEM/bundle encoder and validity/SAN parser in `tests/fuzz`
- [X] T033 [P] [US1] Integration test (testcontainers): empty tenant → CA auto-gen → issue → download cert+chain+bundle validates → renew → revoke in `tests/integration/issue_test.go`

### Implementation for User Story 1

- [X] T034 [P] [US1] Implement `internal/ca` (per-tenant/trust-domain self-signed root/intermediate auto-generation on first use, sealed CA key, `cas` rows + bundle assembly)
- [X] T035 [US1] Implement issuer service in `internal/issue` issuers.go (create/read/update/delete issuers, one default per trust domain, sealed settings/secrets never returned)
- [X] T036 [US1] Implement issuance in `internal/issue` (verify entitlement to the SPIFFE id, mint from chosen/default issuer, sign CSR or generate keypair, record `issued_certificates` + `lcm_certificate_log`, seal generated key, return key once)
- [X] T037 [US1] Implement certificate lifecycle in `internal/issue` (list/get/update-metadata; status active|expiring|expired|revoked derivation; delete)
- [X] T038 [US1] Implement synchronous renew and revoke actions in `internal/issue` (renew reissues same SPIFFE id; revoke sets status + records `revocations`)
- [X] T039 [US1] Implement download/bundle assembly (cert + chain + trust bundle; key only when the module generated it, once)
- [X] T040 [US1] Wire US1 HTTP handlers in `internal/httpapi`: issuers CRUD, `dns-providers` list stub, certificates list/get/update/issue/download/renew/revoke/remove with permissions + audit
- [X] T041 [US1] Emit audit entries (issued, renewed, revoked) via `internal/audit` for every US1 operation

**Checkpoint**: US1 fully functional and independently testable — the MVP.

---

## Phase 4: User Story 2 — Control who may issue, read and revoke (Priority: P2)

**Goal**: fine-grained Zanzibar permissions on certificates and issuers (grant/revoke/list/check/effective, list-accessible, list-all) with tenant-wide grants; `not_found` masking across boundaries.

**Independent Test**: an owner grants a viewer read-only and an editor issue/renew; the viewer cannot mint or revoke; an unreadable object returns `not_found`.

### Tests for User Story 2 (write FIRST, confirm failing) ⚠️

- [X] T042 [P] [US2] Contract test: OpenAPI grants/access paths ↔ routes in `tests/contract/openapi_test.go`
- [X] T043 [P] [US2] Integration test: entitlement matrix (viewer read-only, editor issue/renew, above-granter rejected, tenant grant) in `tests/integration/authz_test.go`
- [X] T044 [P] [US2] Negative security test: unreadable certificate/issuer returns `not_found` not `forbidden`, and cross-tenant access is denied (SR-005) in `tests/integration`

### Implementation for User Story 2

- [X] T045 [US2] Implement grant service in `internal/authz` grants.go (grant/revoke with above-granter guard, optional expiry, tenant/role/user subjects)
- [X] T046 [US2] Wire US2 HTTP handlers in `internal/httpapi`: grants list/create/revoke, access check/effective/accessible with permissions + audit
- [X] T047 [US2] Enforce `use`/issue entitlement from US1 issuance and revoke against grants (replace the interim owner/tenant check) and apply `not_found` masking on all single reads

**Checkpoint**: US1 and US2 both work; access is enforced and existence is not disclosed.

---

## Phase 5: User Story 3 — Enroll a workload and keep its SVID fresh (Priority: P3) ⭐ differentiator

**Goal**: enroll via Freya platform identity or a short-lived auth-minted token (never a static secret); auto-approve or manual requests → async jobs; distributed automated renewal; live certificate-update events over SSE (browser) and gRPC `Agent.Watch` (workload) for zero-downtime rotation; report/list installed certs; deployment targets.

**Independent Test**: a workload with a Freya identity enrolls (auto-approve on), receives an SVID, the scheduler renews it before expiry, and a fresh SVID arrives on its open stream; manual mode yields a pending request an approver can approve/reject.

### Tests for User Story 3 (write FIRST, confirm failing) ⚠️

- [X] T048 [P] [US3] Contract test: OpenAPI enroll/requests/jobs/installed/deployment-targets/stream paths ↔ routes in `tests/contract/openapi_test.go`
- [X] T049 [P] [US3] Contract test: `lcm.v1` proto (SVID, Enrollment, Events, Agent.Watch) ↔ grpc servers in `tests/contract/proto_test.go`
- [X] T050 [P] [US3] Contract test: SSE event frame + Last-Event-ID replay shape against `contracts/stream.md`
- [X] T051 [P] [US3] Unit test `internal/renew` scheduler with fake clock (SQL lease `FOR UPDATE SKIP LOCKED`, worker pool, renewal window, no duplicate for one due cert — SC-003) — must fail
- [X] T052 [P] [US3] Unit test `internal/enroll` (platform-identity + enrollment-token paths; token replay rejected; static secret rejected) — must fail
- [X] T053 [P] [US3] Negative security test: enrollment-token replay/expiry rejected, forged gRPC service identity rejected (SR-002/SR-003) in `tests/integration`
- [X] T054 [P] [US3] Fuzz test: SSE event frame encoder and enrollment-token parser in `tests/fuzz`
- [X] T055 [P] [US3] Integration test: enroll (auto-approve) → SVID; scheduler renews before expiry; fresh SVID on open SSE + gRPC stream within 2s (SC-004); manual mode → pending request → approve in `tests/integration/enroll_renew_test.go`

### Implementation for User Story 3

- [X] T056 [P] [US3] Implement `internal/stream` Valkey per-tenant event fan-out (`XADD MAXLEN ~ 10000`, heartbeat, Last-Event-ID replay) mirroring `services/notification/internal/stream`
- [X] T057 [P] [US3] Implement `internal/stream/valkeykv` (or reuse) for renewal lease + rate-limit counters
- [X] T058 [US3] Implement `internal/enroll` (enroll via platform identity or auth-minted enrollment token per `contracts/auth-changes.md`; auto-approve vs manual request creation; SR-002 entitlement)
- [X] T059 [US3] Implement certificate requests in `internal/enroll` requests.go (create/list/get/approve/reject; status pending|approved|rejected|issued)
- [X] T060 [US3] Implement certificate jobs in `internal/enroll` jobs.go (queued|processing|completed|failed; get-status/get-result/list/cancel/retry; enqueue on approve)
- [X] T061 [US3] Implement `internal/renew` distributed scheduler (SQL lease claim, worker pool, renew within window, fraction-of-TTL for short-lived, days-before for long; publish renewed events; no duplicates)
- [X] T062 [US3] Implement installed-certificate reporting + list and `internal/deploy` deployment targets (create/list, push/deploy a certificate)
- [X] T063 [US3] Wire US3 HTTP handlers in `internal/httpapi`: enroll, requests, jobs, installed, deployment-targets, and the SSE `stream` endpoint (≤5 streams/person, 429 over)
- [X] T064 [US3] Implement `internal/grpcapi` SVID (Issue/Renew/Revoke/Verify/GetTrustBundle), Enrollment (Enroll), Events (Publish) and Agent (Watch stream) services over the US1/US3 services
- [X] T065 [P] [US3] Implement `pkg/lcmclient` and `cmd/lcm-agent` (enroll, download, auto-renew via Agent.Watch, wire into Freya file/spiffe identity provider)
- [ ] T066 [US3] Cross-service: mint + verify short-lived enrollment tokens in `services/auth` per `contracts/auth-changes.md` (+ `authclient` verify helper)

**Checkpoint**: US1–US3 work; the SVID-lifecycle differentiator (enroll + auto-renew + live rotation) is functional.

---

## Phase 6: User Story 4 — ACME issuers, external notifications and credentials (Priority: P4)

**Goal**: ACME/Let's-Encrypt (DNS-01) issuers with pluggable DNS providers; per-tenant tenant secrets (ACME account keys, DNS credentials) sealed and write-only; HMAC-signed outbound webhooks with retries; publish lifecycle events to other modules.

**Independent Test**: an admin stores a DNS credential as a tenant secret, creates an ACME issuer that solves a DNS-01 challenge (mock ACME/DNS), issues a publicly-trusted cert, and a configured webhook receives a signed callback; the secret is never returned.

### Tests for User Story 4 (write FIRST, confirm failing) ⚠️

- [X] T067 [P] [US4] Contract test: OpenAPI secrets/webhooks paths ↔ routes in `tests/contract/openapi_test.go`
- [X] T068 [P] [US4] Unit test `internal/acme` against in-process fake ACME + fake DNS provider (DNS-01 solve, account-key sealing) — must fail
- [X] T069 [P] [US4] Negative security test: tenant-secret values and webhook signing secrets never appear in listings/exports/events/webhook bodies/logs (SR-001, SC-002); oversized webhook payload refused (SR-004) in `tests/integration`
- [X] T070 [P] [US4] Fuzz test: webhook HMAC signer/payload encoder in `tests/fuzz`
- [ ] T071 [P] [US4] Integration test: store DNS secret → ACME issuer → DNS-01 issue (mock) → webhook receives HMAC-signed callback in `tests/integration/acme_webhook_test.go`

### Implementation for User Story 4

- [X] T072 [US4] Implement tenant secrets in `internal/issue` secrets.go (create/list/get/update/delete/rotate; sealed; write-only; in-use guard)
- [X] T073 [P] [US4] Implement `internal/acme` (x/crypto/acme + lego DNS-01 providers per `contracts/acme-dns.md`; account key sealed; DNS-provider registry + required-fields listing)
- [X] T074 [US4] Extend issuer service + issuance to support ACME issuers (order, DNS-01 solve, finalize) and wire the `dns-providers` list handler
- [X] T075 [P] [US4] Implement `internal/webhook` (endpoint CRUD; HMAC-SHA256 signing; bounded payload; retries with backoff; credential scrubbing)
- [X] T076 [US4] Implement lifecycle event publishing to other modules (via `notifyclient` and/or Valkey pub-sub) for certificate.issued/renewed/revoked/failed
- [X] T077 [US4] Wire US4 HTTP handlers in `internal/httpapi`: secrets, webhooks with permissions + audit (secret rotated event)

**Checkpoint**: US1–US4 work; ACME/DNS issuance, tenant secrets, webhooks and event publishing functional.

---

## Phase 7: User Story 5 — Operate, audit and recover (Priority: P5)

**Goal**: append-only tamper-evident audit trail; trust-bundle + revocation-list/CRL distribution with bundle rotation and revocation-window propagation; per-tenant + system statistics; tenant backup export/import (credentials only on request, skip/overwrite).

**Independent Test**: an operator issues + revokes a certificate, confirms both in the audit trail, sees the revocation in the feed/CRL within the propagation window, reads statistics, and round-trips a backup export→import.

### Tests for User Story 5 (write FIRST, confirm failing) ⚠️

- [X] T078 [P] [US5] Contract test: OpenAPI trust-bundle/revocations/crl/stats/audit/backup/health paths ↔ routes in `tests/contract/openapi_test.go`
- [X] T079 [P] [US5] Contract test: backup document validates against `api/schema/backup.schema.json` in `tests/contract/backup_test.go`
- [X] T080 [P] [US5] Negative security test: credential-free export contains no key material (SC-002); import bounds payload size (SR-004); backup respects tenant RLS in `tests/integration`
- [X] T081 [P] [US5] Fuzz test: backup parser in `tests/fuzz`
- [X] T082 [P] [US5] Integration test: issue → revoke → revocation visible in feed + CRL within propagation window (SR-006); audit trail records both; backup export → import (skip + overwrite) round-trips in `tests/integration/operate_test.go`

### Implementation for User Story 5

- [X] T083 [US5] Implement trust-bundle serving + rotation and revocation feed + CRL generation in `internal/revoke` (publish revocation so auth revocation feed / identity RevocationChecker drop the SVID within the window)
- [X] T084 [P] [US5] Implement `internal/stats` (certificates by status, issuers, jobs, clients, expiring soon, recent errors, open_streams; per-tenant + system)
- [X] T085 [P] [US5] Implement `internal/transfer` backup export/import (issuers, issued-cert metadata, permissions, tenant secrets; credentials only on request; skip/overwrite; bounded import) against the backup schema
- [X] T086 [US5] Implement the audit-trail read endpoint (filter by event_type/actor/time; live subject-name resolution; no key material)
- [X] T087 [US5] Wire US5 HTTP handlers in `internal/httpapi`: trust-bundle, revocations, crl, stats, audit, backup export/import, health with permissions + audit

**Checkpoint**: all five user stories independently functional.

---

## Phase 8: UI (Module Federation remote)

**Purpose**: the Materio-styled remote composed by the platform shell; identity/tenant/roles/names from auth.

- [X] T088 [P] Scaffold the `ui/` Vue 3 + Vuetify 4 Module Federation remote (exposes, `/m/lcm/` mount, `authclient`/directory wiring) mirroring `services/notification/ui`
- [X] T089 [P] Implement dashboard (statistics) + issuers list/editor views with Pinia stores
- [X] T090 [P] Implement certificates/issued-certificates list, detail drawer and download
- [X] T091 [P] Implement certificate-requests/jobs (approve/reject), certificate-permissions manager, tenant-secrets manager, and audit-log views
- [X] T092 [P] Vitest unit tests for the stores/components and a Playwright + axe journey through the gateway (including the live stream)

---

## Phase 9: Polish & Cross-Cutting Concerns

- [X] T093 [P] Documentation in `services/lcm/docs/` (README, operations, KEK/bundle rotation, agent usage) and `deploy` notes
- [X] T094 [P] Add remaining unit tests to reach ≥80% overall and 100% on `internal/{authz,sealed,stream,ca,csr}` and the ACME/DNS credential path
- [X] T095 [P] Automated key-material scan test asserting SC-002 across listings, exports, events, webhook bodies and captured logs
- [X] T096 Run `gosec` and `govulncheck`; justify any new dependency (Constitution VI)
- [X] T097 Security hardening + constitution compliance review (all seven principles); confirm SR-001..SR-006
- [ ] T098 Run `quickstart.md` end-to-end validation against the dev stack (SC-001..SC-005)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (P1)**: no dependencies.
- **Foundational (P2)**: depends on Setup; BLOCKS all user stories.
- **User Stories (P3–P7)**: all depend on Foundational.
  - US2 depends on US1 (grants enforce US1 issuance/revoke; T047 replaces the interim check).
  - US3 depends on US1 (issuance) and reuses US2 entitlement; independently testable with auto-approve.
  - US4 depends on US1 (issuer/issuance) for ACME issuers.
  - US5 depends on US1 (certs to audit/revoke/back up).
- **UI (P8)**: depends on the API stories it surfaces (US1–US5).
- **Polish (P9)**: depends on all desired stories.

### Within Each Story

- Tests written and FAILING before implementation (Principle IV).
- Models/stores → services → endpoints → audit wiring.

### Parallel Opportunities

- Setup: T003–T007 in parallel.
- Foundational: T008/T010/T011/T013/T014/T016/T018/T020/T021 in parallel where files differ; T009→T012, T014→T015, T016→T017, T018→T019 are ordered.
- Once Foundational completes, US1–US5 can be staffed in parallel (respecting the story dependencies above).
- Within a story, all `[P]` test tasks run together, then `[P]` implementation files.
- UI tasks T088–T092 are largely parallel.

---

## Parallel Example: User Story 1

```bash
# Tests first (parallel):
Task: "Contract test OpenAPI issuer+certificate paths in tests/contract/openapi_test.go"
Task: "Unit test internal/ca with fake clock"
Task: "Unit test internal/issue (mint/generate/entitlement)"
Task: "Negative security test: entitlement refusal + no key leak"
Task: "Fuzz test PEM/bundle encoder"
Task: "Integration test: CA auto-gen → issue → download → renew → revoke"

# Then implementation:
Task: "Implement internal/ca (self-signed CA auto-gen + bundle)"
```

---

## Implementation Strategy

### MVP First (User Story 1)

1. Phase 1 Setup → 2. Phase 2 Foundational → 3. Phase 3 US1 → **STOP & VALIDATE** (issue/download/renew/revoke) → demo.

### Incremental Delivery

Foundation → US1 (MVP) → US2 (access) → US3 (enroll+renew+live rotation, the differentiator) → US4 (ACME/webhooks/secrets) → US5 (audit/revocation/stats/backup) → UI → Polish. Each story ships independently.

### Parallel Team Strategy

After Foundational: Dev A on US1→US2, Dev B on US3 (+agent/auth token), Dev C on US4, Dev D on US5; UI dev follows each API surface.

---

## Notes

- Every story touches crypto/auth/secrets → each carries negative security tests; parsing/crypto boundaries add fuzz tests (CSR, SPIFFE id, PEM/bundle, SSE frame, enrollment token, webhook signer, backup).
- 100% coverage on `internal/{authz,sealed,stream,ca,csr}` + ACME/DNS credential path; ≥80% overall.
- No custom cryptography; stdlib + `x/crypto/acme` + `lego` only (Constitution VI).
- Module must NOT own the shared `/ui` prefix; the remote is reached via `/m/lcm/`.
- Commit after each task or logical group; verify tests fail before implementing.
