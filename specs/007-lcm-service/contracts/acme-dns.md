# Contract: ACME issuers and DNS-01 providers (lcm)

Internal contract for `internal/acme` (research R2, R12).

## Issuer (ACME)

An ACME issuer holds: directory URL (Let's-Encrypt prod/staging or a private
ACME), a contact email, an ACME account key (a tenant secret, sealed), and a
named DNS provider with its credential (a tenant secret, sealed). Issuance:
create/reuse the ACME account -> request an order for the certificate's DNS SANs
-> solve DNS-01 by writing the `_acme-challenge` TXT record via the provider ->
poll until valid -> finalize with the CSR -> download the chain -> record the
issued certificate. Runs as an async job (queued/processing) with bounded
retries; every error is scrubbed of credentials.

## DNS providers

Backed by `github.com/go-acme/lego/v4` DNS providers. Supported set (parity with
tangra): `cloudflare`, `route53`, `gcloud`, `digitalocean`, `acme-dns`,
`pdns` (PowerDNS), `hurricane` (HE), `httpreq` (HTTP request), `easydns`, and
`exec`/generic. The API exposes:

- `GET /api/lcm/v1/dns-providers` -> `[{name, display_name, fields:[{key, label, secret bool, required bool}]}]`
- The `fields` marked `secret` are stored as tenant secrets and referenced by the
  issuer; they are never returned.

## Tests

Against Pebble (a small ACME test server) and a mock DNS provider that records
the TXT writes, so the full DNS-01 flow runs in integration without real DNS or
Let's-Encrypt. `FuzzChallengeName`/`FuzzProviderConfig` guard parsing. No
provider credential appears in any log or error (marker scan).
