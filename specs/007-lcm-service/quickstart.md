# Quickstart: LCM — Certificate & SVID Lifecycle Management

Validates the feature end to end on the development stack. Each section maps to a
user story and runs through the gateway exactly as a browser or workload would.

## Prerequisites

- The platform dev stack (gateway + auth) running, as for warden/notification.
- `make -C services/lcm compose-up` (TimescaleDB, Valkey, a Pebble/mock ACME
  server and a mock DNS provider on their own ports).
- A dev KEK at `services/lcm/deploy/kek.dev`; the gateway allow-list entry
  `spiffe://example.org/svc/lcm=/api/lcm,/ui;lcm`; the auth policy admitting the
  lcm service on the enrollment-token and directory RPCs (contracts/auth-changes.md).

## 1. Stack and gates

```bash
make -C services/lcm cover fuzz redaction-scan   # unit gate (100% crypto/authz/sealed/stream), fuzz, no material leak
make -C services/lcm test-integration            # tagged end-to-end suite (Docker)
(cd services/lcm/ui && npm ci && npm run build)  # federated remote
```

## 2. Start and register

```bash
make -C services/lcm compose-up
go run ./services/lcm/cmd/lcmsvc -config services/lcm/deploy/dev.yaml   # or the built binary with -tags ui
```

Covers: the module registers with the gateway, the browser API answers 401
without a token and 200 for the operator, health is green, and the tenant CA is
generated on first issuance.

## 3. Issuers and certificate/SVID issuance (US1)

```bash
go test -tags integration ./services/lcm/tests/integration -run 'TestIssuers|TestIssue' -v
```

Covers: first issuance auto-generates the tenant self-signed CA; a CSR for
`spiffe://<td>/workload/api` is signed and an issued-certificate recorded;
download returns cert + chain + bundle and the private key only when the module
generated it (once); renew/force-renew/revoke/delete; the chain validates against
the bundle; the CA key and private keys never appear in any listing/export/log
(marker scan). Manual: **Issuers -> New**, **Certificates -> Issue**, download.

## 4. Access (US2)

```bash
go test -tags integration ./services/lcm/tests/integration -run 'TestAccess' -v
```

Covers: owner/editor/viewer/sharer matrix on a certificate and an issuer
including the `use`/issue action; a viewer downloads but cannot renew/revoke; an
issuer-granted subject mints; an ungranted or cross-tenant caller gets
`not_found`; granter cannot exceed own relation; every grant and refusal audited.

## 5. Enrollment, renewal and live distribution (US3)

```bash
go test -tags integration ./services/lcm/tests/integration -run 'TestEnroll|TestRenew|TestStream' -v
(cd services/lcm && go run ./cmd/lcm-agent enroll --spiffe spiffe://example.org/workload/demo --out /tmp/svid)
```

Covers: a workload enrolls with its Freya identity or an auth-minted token (no
shared secret accepted); auto-approve issues immediately, manual approval queues
a request; the async job reports status; the renewal scheduler renews a due
certificate exactly once and pushes a `renewed` event to an open stream within
2 s; reconnect with `Last-Event-ID` replays the gap; the agent rotates the SVID
on disk so a Freya file-provider service picks it up.

## 6. ACME, secrets, webhooks, deployment (US4)

```bash
go test -tags integration ./services/lcm/tests/integration -run 'TestAcme|TestSecrets|TestWebhook|TestDeploy' -v
```

Covers: a DNS credential stored as a tenant secret; an ACME issuer that solves a
DNS-01 challenge against the mock provider and Pebble; a certificate issued
through ACME; an HMAC-signed `certificate.issued` webhook delivered with retries;
a deployment recorded and a lifecycle event published; the secret value never
appears in any response/event/webhook/log.

## 7. Operate: audit, trust bundle, revocation, statistics, backup (US5)

```bash
go test -tags integration ./services/lcm/tests/integration -run 'TestAudit|TestBundle|TestRevocation|TestOps|TestBackup' -v
```

Covers: every mutation audited with no key material; the trust bundle served and
rotated (new root added before the old removed); a revoked serial appears in the
CRL and is dropped by a verifier via the auth revocation feed within the
propagation window; statistics reflect issuance/expiry; a 100-certificate backup
round-trips (export without credentials -> no secret in the file -> import
skip/overwrite) in < 10 s.

## 8. UI through the gateway

```bash
(cd services/lcm/ui && PW_CHANNEL=chrome E2E_OPERATOR_EMAIL=... E2E_OPERATOR_PASSWORD=... npx playwright test)
```

Specs: `dashboard`, `issuers`, `certificates`, `requests`, `permissions`,
`secrets`, `audit`, each with an axe check (no critical violations).

## 9. Redaction scan and coverage

```bash
make -C services/lcm redaction-scan   # markers LCM-MARKER-KEY-, LCM-MARKER-SECRET- absent from logs, audit, exports-without-credentials
make -C services/lcm cover            # gate: 100% on the crypto/authz/sealed/stream packages, >= 80% overall
```
