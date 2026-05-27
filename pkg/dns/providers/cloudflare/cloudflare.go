package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/providers/dns/cloudflare"

	"github.com/go-tangra/go-tangra-lcm/pkg/dns"
)

type ChallengeProviderConfig struct {
	DnsApiToken           string `json:"dnsApiToken"`
	ZoneApiToken          string `json:"zoneApiToken,omitempty"`
	DnsPropagationTimeout int32  `json:"dnsPropagationTimeout,omitempty"`
	DnsTTL                int32  `json:"dnsTTL,omitempty"`
}

// challengeProvider wraps lego's Cloudflare DNS provider, embedding it so that
// Present, CleanUp and Timeout remain promoted (lego relies on the
// challenge.ProviderTimeout assertion), while adding orphaned-record cleanup
// via the dns.OrphanedChallengeCleaner capability.
type challengeProvider struct {
	*cloudflare.DNSProvider
	client *cfClient
}

var _ dns.OrphanedChallengeCleaner = (*challengeProvider)(nil)

func NewChallengeProvider(config *ChallengeProviderConfig) (dns.ACMEChallenger, error) {
	if config == nil {
		return nil, errors.New("the configuration of the acme challenge provider is nil")
	}
	if config.DnsApiToken == "" {
		return nil, errors.New("cloudflare: dnsApiToken is required")
	}

	providerConfig := cloudflare.NewDefaultConfig()
	providerConfig.AuthToken = config.DnsApiToken
	providerConfig.ZoneToken = config.ZoneApiToken
	if config.DnsPropagationTimeout != 0 {
		providerConfig.PropagationTimeout = time.Duration(config.DnsPropagationTimeout) * time.Second
	}
	if config.DnsTTL != 0 {
		providerConfig.TTL = int(config.DnsTTL)
	}

	provider, err := cloudflare.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return nil, err
	}

	// Zone lookups need Zone:Read. When the operator did not split the
	// permissions into a separate zone token, the DNS token must carry both
	// (the setup lego documents), so reuse it.
	zoneToken := config.ZoneApiToken
	if zoneToken == "" {
		zoneToken = config.DnsApiToken
	}

	return &challengeProvider{
		DNSProvider: provider,
		client: &cfClient{
			httpClient: &http.Client{Timeout: 30 * time.Second},
			baseURL:    defaultAPIBaseURL,
			zoneToken:  zoneToken,
			dnsToken:   config.DnsApiToken,
		},
	}, nil
}

// acmeChallengePrefix is the reserved label under which ACME DNS-01 validation
// records live. Deletion is hard-scoped to names beginning with it so that
// unrelated TXT records (SPF, DKIM, DMARC, verification tokens) are never
// touched, even if a caller passes a bad FQDN or the API returns extra rows.
const acmeChallengePrefix = "_acme-challenge."

// CleanupOrphanedChallengeRecords deletes the TXT records at fqdn before a new
// ACME order begins, clearing leftovers from a previous failed run. It only
// ever removes records whose name is exactly fqdn and whose type is TXT, and
// refuses any fqdn that is not an "_acme-challenge" name. It is best-effort:
// callers log a returned error and proceed with issuance.
func (p *challengeProvider) CleanupOrphanedChallengeRecords(ctx context.Context, fqdn string) error {
	fqdn = strings.TrimSuffix(fqdn, ".")

	// Safety guard: never operate on anything but an ACME challenge name. This
	// makes it impossible to delete an apex SPF/DKIM record by mistake.
	if !strings.HasPrefix(fqdn, acmeChallengePrefix) {
		return fmt.Errorf("cloudflare: refusing to clean non-challenge name %q (must start with %q)", fqdn, acmeChallengePrefix)
	}

	zoneID, err := p.client.findZoneID(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("cloudflare: locate zone for %q: %w", fqdn, err)
	}

	records, err := p.client.listTXTRecords(ctx, zoneID, fqdn)
	if err != nil {
		return fmt.Errorf("cloudflare: list TXT records for %q: %w", fqdn, err)
	}

	var failed []string
	for _, rec := range records {
		// Defense-in-depth: trust nothing from the list filter. Only delete an
		// exact-name TXT record under the challenge prefix.
		if rec.Type != "TXT" || rec.Name != fqdn || !strings.HasPrefix(rec.Name, acmeChallengePrefix) {
			continue
		}
		if delErr := p.client.deleteRecord(ctx, zoneID, rec.ID); delErr != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", rec.ID, delErr))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("cloudflare: failed to delete orphaned records for %q: %s", fqdn, strings.Join(failed, "; "))
	}
	return nil
}
