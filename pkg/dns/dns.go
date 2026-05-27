package dns

import (
	"context"
	"strings"

	"github.com/go-acme/lego/v4/challenge"
)

// ACMEChallenger is the interface a DNS provider must implement to solve ACME
// DNS-01 challenges. It is an alias of lego's challenge.Provider.
type ACMEChallenger = challenge.Provider

// OrphanedChallengeCleaner is an optional capability a DNS provider may
// implement to remove "_acme-challenge" TXT records left behind by previous,
// failed ACME runs.
//
// The certificate issuer calls CleanupOrphanedChallengeRecords once per
// distinct challenge FQDN before starting a new order, so that a stale record
// (whose value may match a CA-reused authorization) cannot collide with the
// record the new order needs to create. For Cloudflare such a collision
// surfaces as API error 81058 "An identical record already exists".
//
// Implementations MUST be best-effort: a returned error is logged by the caller
// and does not abort issuance.
type OrphanedChallengeCleaner interface {
	CleanupOrphanedChallengeRecords(ctx context.Context, fqdn string) error
}

// ChallengeFQDN returns the DNS-01 challenge record name for a certificate
// domain. A leading wildcard label and any trailing dot are stripped, so both
// "*.factory.bg" and "factory.bg" map to the same name
// "_acme-challenge.factory.bg". Callers covering both an apex and its wildcard
// should de-duplicate the results.
func ChallengeFQDN(domain string) string {
	base := strings.TrimPrefix(domain, "*.")
	base = strings.TrimSuffix(base, ".")
	return "_acme-challenge." + base
}
