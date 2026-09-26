# LCM — Certificate & SVID Lifecycle Management

`lcm` is a tenant-scoped certificate authority and SVID lifecycle service for the
Freya platform. It is the platform's SPIFFE CA: it issues and manages the
lifecycle of X.509-SVIDs (`spiffe://<trust-domain>/<path>`) for platform
workloads and external clients, and is the production replacement for the
throwaway `cmd/freya-devca` dev CA.

It mirrors the `services/notification` module: a Go service on the Freya SPIFFE
mTLS channel, a gateway-facing browser API verified with the platform token, a
`lcm.v1` gRPC surface for modules and workload agents, TimescaleDB with
per-tenant row-level security, and a Vue 3 / Vuetify Module Federation remote.

## What it does

- **Issuers & CA** — a self-signed root/intermediate CA auto-generates per
  tenant/trust-domain on first use; additional self-signed and ACME (DNS-01)
  issuers can be added. One default issuer per trust domain. CA and issuer
  credentials are sealed with envelope encryption and never returned.
- **Issuance** — a workload submits a CSR (or asks the service to generate the
  key) bound to a requested SPIFFE id; the service verifies the requester is
  entitled to that identity, mints the SVID, and returns cert + chain + bundle
  (the private key only when it generated it, once).
- **Enrollment** — a workload enrolls with its Freya platform identity or a
  short-lived auth-minted enrollment token (never a static shared secret);
  auto-approve or a manual request → async job workflow.
- **Automated renewal** — a distributed renewal scheduler (SQL lease claim,
  `FOR UPDATE SKIP LOCKED`) renews SVIDs before expiry.
- **Live distribution** — a per-user SSE stream (browser) and a gRPC
  `Agent.Watch` stream (workloads) deliver issued/renewed/revoked events so a
  workload rotates its SVID with no downtime.
- **Access** — Zanzibar relations (owner/editor/viewer/sharer + `use`) on
  certificates and issuers; the `use` action gates issuance/enrollment.
- **Revocation & trust** — revoking a cert publishes a revocation feed and a
  signed CRL, and the service serves the trust bundle per trust domain.
- **Operations** — tenant secrets, HMAC-signed webhooks, an append-only audit
  trail, statistics, and tenant backup export/import.

## Permissions and module roles

lcm registers with auth as module `lcm`, display name "Certificates" (auth SDK
`authclient.Registration`, feature 019), at start, retrying every 5 s until
auth accepts, then every five minutes: its permissions, the module roles
(`pkg/lcmmanifest.Roles`) and the built-in role grants
(`pkg/lcmmanifest.Grants`). Module roles are locked in auth; administrators
assign them or clone them into custom roles:

| Role | Display name | Permissions |
|---|---|---|
| `administrator` | Certificates administrator | all fourteen lcm permissions |
| `operator` | Certificates operator | certificates:read, certificates:issue, certificates:manage, certificates:revoke, issuers:read, jobs:read, jobs:manage, enrollment:enroll |
| `viewer` | Certificates viewer | certificates:read, issuers:read, jobs:read |

The Zanzibar relations on certificates and issuers still apply on top of any
role. Skipped built-in grants (warn) and rejected roles (error) are logged as
`auth registration: ...`.

## Layout

```
api/{openapi,proto/lcm/v1,schema}   embedded browser API, generated lcm.v1, backup schema
cmd/lcmsvc                          service binary (run | bootstrap)
cmd/lcm-agent                       workload daemon (enroll, download, auto-renew)
internal/                           config, store/repo/memstore, sealed, audit, authz,
                                    ca, csr, acme, issue, enroll, renew, revoke, stream,
                                    deploy, secrets, webhook, transfer, stats, httpapi, grpcapi, app
pkg/lcmmanifest                     gateway manifest (routes, permissions, CASL, nav)
pkg/lcmclient                       Go client for modules + the agent
ui/                                 Vue 3 + Vuetify Module Federation remote
tests/                              contract, integration, fuzz, security
```

## Running

```
make compose-up                     # TimescaleDB, Valkey, Pebble (ACME), challtestsrv (DNS)
go run ./cmd/lcmsvc bootstrap -config deploy/dev.yaml   # migrate + KEK check + health
go run -tags "ui" ./cmd/lcmsvc -config deploy/dev.yaml   # serve (with the remote)
```

Register with the gateway's allow-list before it will accept the module (see
`services/gateway` bootstrap). Ports: gRPC 9945, HTTP 9946, admin 9591,
TimescaleDB 5435, Valkey 6382 (compose project `lcm`).

## Testing

```
make test              # unit
make cover             # unit + coverage gate (>=80% total, 100% security pkgs)
make fuzz              # fuzz targets
make test-integration  # tagged integration (testcontainers)
make lint vuln         # vet + staticcheck + gosec; govulncheck
```
