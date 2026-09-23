package acme

import (
	"context"
	"fmt"
)

// FreyaDNS is the registry name of the platform DNS module provider.
const FreyaDNS = "freya-dns"

// FreyaDNSClient is the DNS module's challenge surface (dns.v1.Challenges over
// SPIFFE mTLS; satisfied by services/dns/pkg/dnsclient). The DNS module serves
// it to the lcm identity only and writes only "_acme-challenge" TXT values
// inside the tenant's own zones.
type FreyaDNSClient interface {
	Present(ctx context.Context, tenantID, domain, fqdn, value string) error
	CleanUp(ctx context.Context, tenantID, domain, fqdn, value string) error
}

// FreyaDNSProvider answers DNS-01 challenges through the platform DNS module
// for one issuer tenant. It holds no credentials (mesh identity replaces them)
// and never surfaces the DNS module's error text.
type FreyaDNSProvider struct {
	client   FreyaDNSClient
	tenantID string
}

// Present publishes the challenge value.
func (p *FreyaDNSProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	if err := p.client.Present(ctx, p.tenantID, domain, fqdn, value); err != nil {
		return fmt.Errorf("%w: freya dns present", ErrProvider)
	}
	return nil
}

// CleanUp removes the challenge value.
func (p *FreyaDNSProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	if err := p.client.CleanUp(ctx, p.tenantID, domain, fqdn, value); err != nil {
		return fmt.Errorf("%w: freya dns cleanup", ErrProvider)
	}
	return nil
}
