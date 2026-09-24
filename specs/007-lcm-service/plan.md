# Implementation Plan: LCM — Certificate & SVID Lifecycle Management

**Branch**: `007-lcm-service` | **Date**: 2026-09-17 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/007-lcm-service/spec.md`.

## Summary

`services/lcm` is a new Freya platform module with the same shape as
`services/warden` and `services/notification`: a Go service on the Freya SPIFFE
mTLS channel that registers with the application gateway, verifies the platform
token forwarded by the gateway with `pkg/authclient`, and stores its data in
TimescaleDB under per-tenant row-level security. It is the platform's
**certificate authority**: it manages the lifecycle of X.509 certificates —
SPIFFE X.509-SVIDs first — issuing them from a per-tenant self-signed CA
(auto-generated on first use) or from ACME/Let's-Encrypt issuers, renewing them
before expiry, distributing them live, and revoking them.

Tangra's authentication model (generic mTLS client certificates + a static
per-tenant shared secret) is removed entirely. Callers reach the module exactly
as every other module is reached: browser traffic through the gateway with a
platform token; service-to-service over Freya SPIFFE mTLS policed by the
callee's `policy.yaml`. A workload **enrolls** for an SVID using its existing
Freya identity or a short-lived enrollment token minted by the auth service —
never a static secret. The module is the production replacement for the
throwaway `cmd/freya-devca` dev CA.

Signing uses the Go standard library (`crypto/x509`, `crypto/ecdsa`/`ed25519`,
`crypto/rand`); the CA/issuer/secret private material is sealed at rest with the
same envelope scheme as warden/notification (AES-256-GCM data key wrapped by a
KEK from file or env). ACME issuance uses `golang.org/x/crypto/acme` with
DNS-01, and the DNS providers reuse the `go-acme/lego` provider set (ten
providers plus a generic one) — the only substantial new dependency, justified
in research.md. The renewal scheduler is an in-service worker with a leased SQL
claim (`FOR UPDATE SKIP LOCKED`), copied from the notification scheduler, so one
instance renews each due certificate. Live distribution is a module-served SSE
route relayed by the gateway plus a `lcm.v1` gRPC stream for workload agents,
both fed by one Valkey stream per tenant (fan-out across instances, bounded
replay). Zanzibar-style access (Owner/Editor/Viewer/Sharer with a `use`/issue
action) is one indexed SQL query, copied from warden without folder
inheritance. The browser API is an OpenAPI document validated by kin-openapi;
the UI is a Vue 3 + Vuetify Module Federation remote composed by the shell.

## Technical Context

**Language/Version**: Go 1.26 (service + workload client); TypeScript 5 / Vue 3 / Vuetify 4 (remote).

**Primary Dependencies**: Freya framework (transport, identity, audit, config, observability); `services/auth/pkg/authclient` (platform-token verification, enrollment-token verification); `services/gateway/pkg/gatewayclient` (registration, manifest); `services/notification/pkg/notifyclient` (optional — relay lifecycle events); pgx + goose (TimescaleDB); kin-openapi (request validation); `github.com/valkey-io/valkey-go` (live event stream, distributed renewal lock, rate limits); stdlib `crypto/x509`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/rand`, `crypto/aes`+`crypto/cipher` (envelope), `crypto/hmac`+`crypto/sha256` (webhook signatures); `golang.org/x/crypto/acme` + `github.com/go-acme/lego/v4` (ACME + DNS-01 providers, research R2); Module Federation runtime (UI). No ORM; no custom cryptography (Constitution VI).

**Storage**: TimescaleDB (`lcm` database, `lcm_app` role, RLS per tenant): `issuers`, `cas` (trust-domain roots + rotation), `certificate_requests`, `certificate_jobs`, `issued_certificates`, `installed_certificates`, `deployment_targets`, `tenant_secrets`, `grants`, `webhook_endpoints`, `revocations`, `lcm_audit_events` (hypertable), `lcm_certificate_log` (hypertable). Valkey: one stream per tenant for live certificate events (`XADD … MAXLEN ~ 10000`), the renewal lease coordinator, rate-limit counters. No file storage (unlike tangra's SQLite + on-disk data dir).

**Testing**: Go unit (memstore double, in-process fake ACME/DNS provider, fake clock for the renewal scheduler and expiry), contract (OpenAPI ↔ routes, `lcm.v1` proto, gateway manifest, `policy.yaml`), fuzz (CSR parser, SPIFFE-id validator, PEM/bundle encoder, SSE event frame, backup parser, webhook signer), integration (testcontainers: TimescaleDB, Valkey, Pebble/mock-ACME, mock DNS; gateway + auth as subprocesses like feature 005/006), Vitest, Playwright + axe through the gateway (including the live stream). Coverage gate: 100% on `internal/{authz,sealed,stream,ca,csr}` and the ACME/DNS credential path, >= 80% overall.

**Target Platform**: Linux server; evergreen browsers through the platform shell; the workload client runs anywhere a Freya service runs.

**Project Type**: web service + federated remote (platform module) + `lcm.v1` gRPC for modules and workload agents + a Go workload client (`pkg/lcmclient`) and optional CLI/daemon.

**Performance Goals**: issue-and-download a certificate end to end < 3 s (SC-001); permission check one SQL query (< 5 ms); live certificate event to an open stream < 2 s (SC-004); renewal delivered before expiry in >=99% of cycles, never duplicated (SC-003); revocation propagated < 10 s in dev (SC-006); 100-certificate backup round trip < 10 s (SC-008).

**Constraints**: no CA/issuer/DNS/ACME key or workload private key in any listing, log, audit, error, event, webhook body or credential-free export (SR-001, scanned with marker values); enrollment refuses static secrets (SR-002); every module call SPIFFE-verified against `policy.yaml` (SR-003); CSR <= 16 KiB, backup upload <= 16 MiB, webhook body <= 64 KiB (SR-004); `not_found` for unreadable resources (SR-005); revocation within the platform propagation window (SR-006); SVID validity clamped to the issuer ceiling; SSE streams capped per person and 5-minute max age like notification.

**Scale/Scope**: tenants up to tens of thousands of workloads and ~1M issued-certificate rows; ~55 HTTP endpoints, `lcm.v1` gRPC (Issuer/SVID service + Events + a workload stream), 8 UI views, ~13 tables, 1 Valkey stream per tenant.

## Constitution Check

*GATE: evaluated against `.specify/memory/constitution.md` (v1.0.0). PASS unless noted.*

- [X] **I. Secure by Default**: auto-approve, ACME plaintext, and short SVID TTLs default to the secure choice; auto-approve-on and any plaintext/dev opt-out is a named config flag that logs a startup warning (mirrors warden/notification `Warnings()`). Private keys are generated by the workload by default (module-generated keys are opt-in and returned once).
- [X] **II. Zero Trust**: browser routes require the gateway platform token (authclient middleware); every `lcm.v1` method is SPIFFE-mTLS-authenticated and policed by `deploy/policy.yaml`; enrollment requires a platform identity or an auth-minted token; per-object Zanzibar authorization runs in the handler before any signing.
- [X] **III. Boundary Validation**: the OpenAPI document schema-validates every browser request (kin-openapi); CSRs, SPIFFE ids, SANs, backups and webhook payloads are parsed with explicit bounds; validity is clamped to the issuer ceiling; rate/size/timeout limits applied at the edge and per handler.
- [X] **IV. Test-First (NON-NEGOTIABLE)**: tasks.md will list tests before implementation; fuzz targets for the CSR parser, SPIFFE-id validator, PEM/bundle encoder, SSE frame, backup parser and webhook signer; negative security tests for enrollment, cross-tenant access and revocation; 100% coverage on the crypto/authz/sealed/stream packages.
- [X] **V. Observability**: every mutation emits one audit event (closed vocabulary, no key material); correlation id propagated; a redaction scan asserts marker values never leak; no new public debug/metrics surface.
- [X] **VI. Supply Chain**: only new dependency is `x/crypto/acme` + `go-acme/lego/v4` for ACME/DNS-01, justified in research.md (re-implementing ACME and ten DNS providers would be far more security-sensitive code); no custom cryptography; `govulncheck` in CI.
- [X] **VII. Simplicity**: explicit typed config; no ORM, reflection or global state; the CA/issuer/scheduler/stream/authz packages mirror existing modules. No Complexity Tracking entries.
- [X] **Threat Model**: the feature touches auth, transport, parsing, secrets and crypto — a STRIDE threat model is in research.md.

*Post-Phase-1 re-check*: the data model, contracts and quickstart introduce no new trust boundary or dependency beyond the above; all gates remain PASS.

## Project Structure

### Documentation (this feature)

```text
specs/007-lcm-service/
|- plan.md              # This file
|- research.md          # Phase 0: decisions R1-R14 + STRIDE
|- data-model.md        # Phase 1: entities, tables, RLS, state machines
|- quickstart.md        # Phase 1: end-to-end validation guide
|- contracts/           # Phase 1: OpenAPI, proto, manifest, schemas, integration contracts
|  |- lcm-api.openapi.yaml
|  |- lcm.v1.proto
|  |- manifest.md
|  |- backup.schema.json
|  |- stream.md
|  |- auth-changes.md
|  |- acme-dns.md
|- tasks.md             # Phase 2 (/speckit-tasks - not created here)
```

### Source Code (repository root)

```text
services/lcm/
|- api/{openapi,proto/lcm/v1,schema}      # embedded browser API, generated lcm.v1, backup schema
|- cmd/lcmsvc/                            # service binary (bootstrap, rotate-kek, rotate-bundle)
|- cmd/lcm-agent/                         # workload CLI/daemon (enroll, download, auto-renew)
|- deploy/                                # compose.yaml, dev.yaml, policy.yaml, init-db.sql, kek.dev
|- internal/
|  |- config store repo repo/repodb memstore   # config, RLS store, repositories, in-memory double
|  |- sealed audit authz                        # envelope, audit, Zanzibar grants
|  |- ca csr acme issue enroll renew revoke     # CA, CSR/SPIFFE parse, ACME/DNS, issuance, enrollment, scheduler, revocation
|  |- stream webhook deploy transfer stats      # live fan-out, webhooks, deployment, backup, statistics
|  |- httpapi grpcapi app                        # OpenAPI server, lcm.v1 servers, wiring + registration
|- pkg/lcmmanifest pkg/lcmclient          # gateway manifest; Go client for modules + agent
|- ui/                                    # Vue 3 + Vuetify Module Federation remote
|- tests/                                 # contract, integration, fuzz

# Cross-service changes (small):
services/auth/...                         # mint + verify short-lived enrollment tokens (contracts/auth-changes.md)
```

**Structure Decision**: a self-contained platform module under `services/lcm`,
copy-and-adapt from `services/warden` and `services/notification` (config,
store/RLS, sealed, audit, authz, stream, transfer, httpapi, grpcapi, app,
manifest, ui), adding the CA/CSR/ACME/issue/enroll/renew/revoke packages that
are specific to a certificate authority. One small cross-service change to auth
for enrollment tokens.

## Complexity Tracking

No constitution violations; no entries.
