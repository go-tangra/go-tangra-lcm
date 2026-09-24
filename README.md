# go-tangra-lcm

Certificate and SVID lifecycle management service for the
[go-tangra v4 platform](https://github.com/go-tangra/go-tangra).

It is the platform's SPIFFE certificate authority. Per tenant and trust domain it
generates a self-signed CA on first use (plus optional ACME DNS-01 issuers), issues
X.509-SVIDs and certificates from CSRs or service-generated keys, enrolls workloads
with their platform identity or a short-lived enrollment token, renews before expiry,
streams issued/renewed/revoked events to browsers (SSE) and workloads (`Agent.Watch`),
and publishes revocations, a signed CRL and the trust bundle. Tenant secrets,
signed webhooks, audit, statistics and backup export/import complete the operator
surface. All key material is sealed with envelope encryption.

Overview: [`docs/README.md`](docs/README.md).
Operations: [`docs/operations.md`](docs/operations.md).
Security review: [`docs/security-review.md`](docs/security-review.md).
Design history: `specs/007-lcm-service`.

## Place in the platform

```
go-tangra/go-tangra          platform module + @go-tangra/ui kit
        |
go-tangra-auth  <---->  go-tangra-portal (gateway)  <---->  go-tangra-lcm
                                                              ^
                                    deployer, dns, workloads (lcm sdk, lcm-agent)
```

- Built on `github.com/go-tangra/go-tangra/v4` (mTLS transports, identity,
  service policy, audit, observability).
- Verifies platform tokens and registers its permissions with the auth SDK
  (`github.com/go-tangra/go-tangra-auth/sdk/v4`).
- Registers with the gateway through the portal SDK
  (`github.com/go-tangra/go-tangra-portal/sdk/v4`), which fronts the browser API
  and the federated UI remote.

## Modules in this repository

| Module | Path | Consumers |
|---|---|---|
| `github.com/go-tangra/go-tangra-lcm/v4` | `/` | the service (`cmd/lcmsvc`), `cmd/lcm-agent`, `cmd/lcm-devca` and `pkg/lcmmanifest` |
| `github.com/go-tangra/go-tangra-lcm/sdk/v4` | `sdk/` | other services and workloads: the `lcm.v1` protobuf API, `pkg/lcmclient` (client and agent loop), `pkg/lcmidentity`, `pkg/dnschallenge` |

The service builds against the in-repo SDK through
`replace github.com/go-tangra/go-tangra-lcm/sdk/v4 => ./sdk`. Consumers use the
SDK's published `sdk/vX.Y.Z` tag.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/lcmsvc` | service binary (serve, `bootstrap`, `version`) |
| `cmd/lcm-agent` | workload daemon: enroll, write cert/key/bundle, auto-renew |
| `cmd/lcm-devca` | offline development CA and per-service SVIDs (development only) |
| `internal/app` | wiring: config, platform, stores, services, HTTP/gRPC |
| `internal/...` | CA, CSR, ACME, issuance, enrollment, renewal, revocation, streams, sealing, authz, secrets, webhooks, backup and their SQL bindings |
| `ui` | Vue 3 + FlyonUI federated remote on `@go-tangra/ui` |
| `api/openapi`, `api/schema`, `sdk/api/proto` | contracts (`lcm.yaml`, backup schema, `lcm.v1`) |
| `deploy` | compose stack, dev configuration, development KEK, policies |
| `tests/{contract,fuzz,integration,security}` | contract, fuzz, Docker-backed integration and security suites |

## Build and test

You need Go 1.26, Node 22, Docker (for integration tests and the image), and a
GitHub token with `read:packages` to install `@go-tangra/ui` from GitHub Packages.

```bash
go build ./... && go vet ./... && go test -race ./...
(cd sdk && go vet ./... && go test -race ./...)
(cd sdk && buf lint)
make test-integration                     # -tags integration, needs Docker
make lint cover fuzz redaction-scan vuln

cd ui
export NODE_AUTH_TOKEN=$(gh auth token)   # ui/.npmrc only references this variable
npm ci && npm run lint && npm run test:unit && npm run build
```

The unit coverage gate requires at least 80 % overall and 100 % for the
crypto, authorization, sealing and stream packages. Generated code, SQL bindings
and wiring are covered by the integration suite instead.

## Run locally

```bash
make compose-up                           # TimescaleDB, Valkey, Pebble (ACME), challtestsrv (DNS)
go run ./cmd/lcmsvc bootstrap -config deploy/dev.yaml
go run -tags ui ./cmd/lcmsvc -config deploy/dev.yaml    # after the ui build
```

## Container image

The image is `ghcr.io/go-tangra/go-tangra-lcm`, built by `.github/workflows/ci.yaml`.
It carries `lcmsvc` (with the embedded UI remote) and `lcm-devca`.

```bash
docker buildx build --secret id=npm_token,env=NODE_AUTH_TOKEN \
  --build-arg APP_VERSION=4.0.0 -t go-tangra-lcm:dev .
docker run --rm go-tangra-lcm:dev version
```

The image runs `lcmsvc -config deploy/dev.yaml` as user `app` (uid 10001).
Production deployments mount their own configuration and key-encryption key.

## Versioning

- Service releases are tagged `vX.Y.Z`. CI publishes the image as `X.Y.Z`,
  `X.Y`, `X` and `sha-<short>`. There is no `latest` tag.
- The SDK is released separately with `sdk/vX.Y.Z` tags. These tags never build an image.
- v4.0.0 rebuilds the service on the go-tangra v4 platform. The v3 line stays on
  the `v3` branch and its `v3.x` tags.
