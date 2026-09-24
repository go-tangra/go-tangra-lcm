# Contract: gateway manifest (lcm)

Built from the embedded OpenAPI document by `pkg/lcmmanifest`, mirroring
warden/notification.

- **Module**: `lcm`; **DisplayName**: `Certificates`; **Version**: `1.0.0`.
- **Prefixes** (owned): `/api/lcm`. The federated remote is reached through the
  gateway per-module relay `/m/lcm/...` -> the module's `/ui/...`; the module does
  **not** own the shared `/ui` prefix (per the notification finding).
- **Exposes**: `./routes`, `./nav`, `./header` (an "expiring soon" bell, optional).
- **Permissions** (registered, granted to built-in roles):
  `certificates:read`, `certificates:manage`, `certificates:issue`,
  `certificates:revoke`, `issuers:read`, `issuers:manage`, `enrollment:enroll`,
  `jobs:read`, `jobs:manage`, `permissions:manage`, `secrets:manage`,
  `webhooks:manage`, `backup:manage`, `stats:read`.
- **Grants** (built-in roles): `owner`/`admin` -> all; `member` ->
  `certificates:read`, `issuers:read`, `enrollment:enroll`, `jobs:read`;
  `auditor` -> `stats:read`, `certificates:read`; `operator` -> `stats:read`.
- **Abilities** (CASL): read/create/update/delete/issue/revoke/use on
  `Certificate` and `Issuer`; manage on `TenantSecret`, `Webhook`,
  `CertificateBackup`; read on `LcmStats`, `LcmAudit`.
- **Methods**: none proxied by the gateway (the `lcm.v1` gRPC is service/workload
  to service only).
- Every route carries `x-freya-permission`; body-heavy routes carry
  `x-freya-max-body-bytes` (backup 16 MiB) and slow ones `x-freya-timeout-seconds`
  (issue/enroll 60, ACME issue 300, backup 120, stream 300). No public routes.
- The wire form validates against the gateway `manifest.schema.json`.
