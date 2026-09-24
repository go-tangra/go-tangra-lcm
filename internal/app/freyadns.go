package app

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-tangra/go-tangra-lcm/sdk/v4/pkg/dnschallenge"
)

// lazyDNS is the DNS module client behind the "freya-dns" ACME provider,
// dialled over SPIFFE mTLS on first use so lcm starts while dns is down. The
// DNS module serves dns.v1.Challenges to the lcm identity only.
type lazyDNS struct {
	app     *App
	service string
	mu      sync.Mutex
	c       *dnschallenge.Client
}

func (l *lazyDNS) client(ctx context.Context) (*dnschallenge.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c == nil {
		conn, err := l.app.Freya.Client(ctx, l.service)
		if err != nil {
			return nil, fmt.Errorf("dns client: %w", err)
		}
		l.c = dnschallenge.New(conn)
	}
	return l.c, nil
}

// Present publishes an ACME DNS-01 value through the DNS module.
func (l *lazyDNS) Present(ctx context.Context, tenantID, domain, fqdn, value string) error {
	c, err := l.client(ctx)
	if err != nil {
		return err
	}
	_, err = c.Present(ctx, tenantID, domain, fqdn, value)
	return err
}

// CleanUp removes an ACME DNS-01 value through the DNS module.
func (l *lazyDNS) CleanUp(ctx context.Context, tenantID, domain, fqdn, value string) error {
	c, err := l.client(ctx)
	if err != nil {
		return err
	}
	_, err = c.CleanUp(ctx, tenantID, domain, fqdn, value)
	return err
}
