# Contract: auth service changes for lcm enrollment

Small additions to `services/auth` so the LCM can enroll workloads without a
static secret (spec US3, research R4).

## New: short-lived enrollment tokens

`auth.v1.Enrollment` (new service, service-to-service only, policed by auth's
`policy.yaml`):

- `MintEnrollmentToken(MintEnrollmentTokenRequest{tenant_id, spiffe_paths[], ttl_seconds, audience="lcm"}) -> {token, expires_at}`
  - an operator/admin action (through the console/gateway) that produces a
  one-time, short-lived (default 10 min) signed token naming the tenant and the
  SPIFFE path(s) a new workload may claim. Rate-limited; audited.
- `VerifyEnrollmentToken(VerifyEnrollmentTokenRequest{token, audience="lcm"}) -> {tenant_id, spiffe_paths[], jti}`
  - called by the LCM to verify a presented token; single-use (the `jti` is
  burned via the auth revocation/replay store).

`pkg/authclient` gains a helper to verify the token (or the LCM calls
`VerifyEnrollmentToken` over the channel). The token is an EdDSA JWT signed by
the auth keys the LCM already trusts for platform tokens.

## Policy

`services/auth/deploy/policy.yaml` gains a rule admitting
`spiffe://example.org/svc/lcm` on `/auth.v1.Enrollment/VerifyEnrollmentToken`
and the existing `/auth.v1.Keys/List`, `/auth.v1.Sessions/RevokedSince`,
`/auth.v1.Authorization/Check`, `/auth.v1.Profiles/Lookup` (names + decisions for
the UI, as notification uses). Minting is admitted for the gateway/console only.

## Revocation feed

Revoking an SVID publishes to the same revocation channel `authclient`
`RevocationChecker` consumes (research R9), so no new verifier plumbing is needed
- a revoked SVID's serial/jti is dropped platform-wide.
