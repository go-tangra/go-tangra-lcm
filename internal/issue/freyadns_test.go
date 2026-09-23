package issue

// T075: an ACME issuer selecting the Freya DNS provider gets a provider bound
// to the issuer's tenant when the DNS module client is wired, and a clear
// dns_provider refusal when it is not.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/go-freya/freya/services/lcm/internal/acme"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
)

type fakeDNS struct{ tenants []string }

func (f *fakeDNS) Present(_ context.Context, tenant, _, _, _ string) error {
	f.tenants = append(f.tenants, tenant)
	return nil
}

func (f *fakeDNS) CleanUp(_ context.Context, tenant, _, _, _ string) error {
	f.tenants = append(f.tenants, tenant)
	return nil
}

func accountKeyPEM(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestACMEIssuerWithFreyaDNS(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	iv, err := f.svc.CreateIssuer(ctx, f.admin, IssuerInput{
		Name: "le", Type: "acme", TrustDomain: "example.org", Enabled: true,
		ACMEDirectoryURL: "https://127.0.0.1:14000/dir", ACMEEmail: "ops@example.org", DNSProvider: acme.FreyaDNS,
		Settings: sealed.Settings{"acme_account_key": accountKeyPEM(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := f.mem.GetIssuer(ctx, f.admin.TenantID, iv.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Not wired: refused as an unusable DNS provider.
	var ve *ValidationError
	if _, err := f.svc.acmeClientFor(issuer); !errors.As(err, &ve) || ve.Field != "dns_provider" {
		t.Fatalf("unwired = %v", err)
	}
	dns := &fakeDNS{}
	f.svc.SetFreyaDNS(dns)
	if _, err := f.svc.acmeClientFor(issuer); err != nil {
		t.Fatalf("wired = %v", err)
	}
	p, err := f.svc.dnsProvider(issuer, sealed.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Present(ctx, "example.com", "_acme-challenge.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	if len(dns.tenants) != 1 || dns.tenants[0] != f.admin.TenantID {
		t.Fatalf("tenant = %v", dns.tenants)
	}
	// Other providers are unaffected by the wiring.
	issuer.DNSProvider = "manual"
	if p, err := f.svc.dnsProvider(issuer, sealed.Settings{}); err != nil {
		t.Fatal(err)
	} else if _, ok := p.(*acme.NoopProvider); !ok {
		t.Fatalf("manual = %T", p)
	}
	f.svc.SetFreyaDNS(nil)
	issuer.DNSProvider = acme.FreyaDNS
	if _, err := f.svc.dnsProvider(issuer, sealed.Settings{}); !errors.Is(err, acme.ErrUnsupportedProvider) {
		t.Fatalf("unset = %v", err)
	}
}
