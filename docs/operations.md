# LCM operations

## KEK rotation

Every CA private key, issuer/ACME/DNS credential, tenant-secret value, webhook
signing secret and service-generated workload key is sealed with envelope
encryption under a 32-byte key-encryption key (`deploy/kek.dev` in development;
a file or environment variable in production — see `kek.source`).

To rotate the KEK, run the service's re-seal path with the new key available
and the old key in the configuration. (The re-seal-all-material command is a
planned ops subcommand; until it ships, rotate by exporting a tenant backup
*with credentials* under the old key and importing it under the new key.)

## Trust-bundle / CA rotation

Each trust domain has one `active` CA. Rotation issues a `next` root, promotes
it to `active` (old → `retiring`), and removes `retiring` after a grace period.
The trust bundle (`GET /api/lcm/v1/trust-bundle?trust_domain=…`) returns the
active and retiring roots so peers keep validating across a rotation.

## Revocation propagation

Revoking a certificate records a revocation row, which feeds:
- `GET /api/lcm/v1/revocations` — the revocation feed the auth service's
  RevocationChecker polls, and
- `GET /api/lcm/v1/crl?trust_domain=…` — a signed CRL.

Verifiers drop a revoked SVID within the platform's revocation-propagation
window (SR-006).

## The workload agent

`cmd/lcm-agent` enrolls a workload, writes `tls.crt`/`tls.key`/`chain.pem`/
`bundle.pem` (key mode 0600, directory 0700) atomically, and auto-renews:
a renewal timer fires within `-renew-before` of expiry, and an `Agent.Watch`
gRPC stream pokes an out-of-band renewal on issued/renewed/revoked events for
the workload's SPIFFE id, reconnecting with capped backoff. It dials the lcm
gRPC endpoint over SPIFFE mTLS (file identity in development; the pooled Freya
identity provider in production).

## Backups

`POST /api/lcm/v1/backup/export` exports issuers, issued-certificate metadata,
permissions and (only with `include_credentials: true`) tenant secrets and
issuer credentials. A credential-free export contains no key material.
`POST /api/lcm/v1/backup/import?mode=skip|overwrite` restores a document
(schema-validated, size-bounded).
