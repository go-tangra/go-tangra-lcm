# go-tangra-lcm

Enterprise-grade Certificate Lifecycle Management service providing X.509 certificate issuance, renewal, distribution, and revocation with mTLS authentication and multi-tenancy support.

## Features

- **Automatic CA Generation** — Self-signed root CA created on first startup
- **Auto-Approval Mode** — Puppet-style automatic certificate signing
- **Multi-Issuer Support** — Self-signed and ACME (Let's Encrypt) issuers
- **Automated Renewal** — Distributed renewal scheduler with Redis-based locking
- **Real-time Streaming** — gRPC streaming for live certificate update notifications
- **Event-Driven** — Redis pub/sub events for certificate lifecycle changes
- **Webhooks** — HTTP callbacks with HMAC signing for external integrations
- **10 DNS Providers** — Cloudflare, Route53, GCloud, DigitalOcean, PowerDNS, and more
- **Multi-Tenant** — Complete tenant isolation with per-tenant shared secrets
- **Audit Trail** — Cryptographically signed audit logs

## gRPC Services

| Service | Port | Purpose |
|---------|------|---------|
| LcmClientService | 9100 | Client registration, cert download, streaming |
| LcmMtlsCertificateService | 9100 | Certificate CRUD, issuance, revocation, renewal |
| LcmCertificateJobService | 9100 | Async certificate request tracking |
| LcmIssuerService | 9100 | Issuer management (self-signed, ACME) |
| AuditLogService | 9100 | Audit log queries |
| CertificatePermissionService | 9100 | Fine-grained access control |
| StatisticsService | 9100 | System-wide metrics |

REST API available on port 8000 via gRPC-Gateway.

## Certificate Lifecycle

```
Client Registration (shared secret)
  → Certificate Request (async job)
    → Auto-Approve / Manual Approve
      → Certificate Issued (event published)
        → Streamed to clients / Webhook notification
          → Auto-Renewal (30 days before expiry)
```

## Configuration

```yaml
data_dir: ./data
default_validity_days: 365
auto_approve_certificates: true
auto_generate_ca: true
shared_secret: "changeme"

renewal:
  enabled: true
  check_interval_seconds: 3600
  worker_count: 2
  default_days_before_expiry: 30

events:
  enabled: true
  topic_prefix: "lcm"

webhooks:
  enabled: false
  endpoints:
    - name: "primary"
      url: "https://example.com/webhooks/lcm"
      event_types: ["certificate.issued", "certificate.failed"]
      secret: "hmac-signing-secret"
```

## DNS Providers (ACME)

Cloudflare, AWS Route53, Google Cloud DNS, DigitalOcean, ACME-DNS, PowerDNS, Hurricane Electric, HTTP Request, EasyDNS, Cloud DNS

## Build

```bash
make build-all          # Build server and client binaries
make build-server       # Build server only
make build-client       # Build CLI client only
make docker             # Build Docker image
make docker-buildx      # Multi-platform (amd64/arm64)
make test               # Run tests
make ent                # Regenerate Ent schemas
```

## Docker

```bash
docker run -p 9100:9100 ghcr.io/go-tangra/go-tangra-lcm:latest
```

Runs as non-root user `lcm` (UID 1000). Data stored in `/app/data`.

## Dependencies

- **Framework**: Kratos v2
- **ORM**: Ent (PostgreSQL, MySQL)
- **ACME**: lego v4
- **Cache/Events**: Redis
- **Protobuf**: Buf
