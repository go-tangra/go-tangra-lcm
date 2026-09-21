# Contract: live certificate stream (lcm)

Two transports over one per-tenant Valkey stream `lcm:events:<tenant>`
(`XADD MAXLEN ~ 10000`, trimmed to the replay window), copied from the
notification stream package.

## Browser SSE - `GET /api/lcm/v1/stream`

- Permission `certificates:read`; `x-freya-timeout-seconds: 300`.
- `text/event-stream`; the module closes at 290 s (below the gateway 300 s route
  ceiling) so the client reconnects; heartbeat every 15 s; `retry: 3000`.
- `Last-Event-ID` replays events published in the last 5 minutes; an id older
  than the window yields a `reset` event.
- Events are scoped to the caller's tenant and to the certificates the caller may
  read; event types `certificate.issued`, `certificate.renewed`,
  `certificate.revoked`, plus `reset`, `bye`.
- Per-person cap (5 streams) and per-tenant cap; a refused stream is `429` and
  audited `stream_refused`.

## Workload gRPC - `lcm.v1.Agent/Watch` (server streaming)

- Called by a workload agent over SPIFFE mTLS; scoped to the agent's own SPIFFE
  id (and any it holds `use` on).
- Delivers `CertificateUpdate{type, certificate_id, spiffe_id, not_after}` so the
  agent downloads and rotates on `renewed`/`issued` and re-enrolls on `revoked`.
- Same replay/heartbeat semantics; the gateway is not involved (direct mTLS).

Frame data never contains key material - only ids, the SPIFFE id and timestamps.
