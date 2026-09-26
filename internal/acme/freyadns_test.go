package acme

// T070: the Freya DNS provider publishes DNS-01 values through the DNS module
// (mesh identity, no stored credentials) for the issuer's tenant; without the
// dependencies it is unsupported; the DNS module's error text never surfaces.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeFreyaDNS struct {
	calls []string
	err   error
}

func (f *fakeFreyaDNS) Present(_ context.Context, tenant, domain, fqdn, value string) error {
	f.calls = append(f.calls, strings.Join([]string{"present", tenant, domain, fqdn, value}, "|"))
	return f.err
}

func (f *fakeFreyaDNS) CleanUp(_ context.Context, tenant, domain, fqdn, value string) error {
	f.calls = append(f.calls, strings.Join([]string{"cleanup", tenant, domain, fqdn, value}, "|"))
	return f.err
}

const issuerTenant = "11111111-1111-7111-8111-111111111111"

func TestFreyaDNSRegistered(t *testing.T) {
	for _, p := range Providers() {
		if p.Name == FreyaDNS {
			if p.DisplayName != "Tangra DNS" || len(p.Fields) != 0 {
				t.Fatalf("freya-dns entry = %+v", p)
			}
			return
		}
	}
	t.Fatal("freya-dns not listed")
}

func TestNewProviderWithFreyaDNS(t *testing.T) {
	fake := &fakeFreyaDNS{}
	p, err := NewProviderWith(FreyaDNS, map[string]string{}, ProviderDeps{FreyaDNS: fake, TenantID: issuerTenant})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.Present(ctx, "*.example.com", "_acme-challenge.example.com", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanUp(ctx, "*.example.com", "_acme-challenge.example.com", "v1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"present|" + issuerTenant + "|*.example.com|_acme-challenge.example.com|v1", "cleanup|" + issuerTenant + "|*.example.com|_acme-challenge.example.com|v1"}
	if len(fake.calls) != 2 || fake.calls[0] != want[0] || fake.calls[1] != want[1] {
		t.Fatalf("calls = %v", fake.calls)
	}
}

func TestFreyaDNSMissingDeps(t *testing.T) {
	for _, d := range []ProviderDeps{{}, {FreyaDNS: &fakeFreyaDNS{}}, {TenantID: issuerTenant}} {
		if p, err := NewProviderWith(FreyaDNS, nil, d); p != nil || !errors.Is(err, ErrUnsupportedProvider) {
			t.Errorf("deps %+v: %v %v", d, p, err)
		}
	}
	if p, err := NewProvider(FreyaDNS, nil); p != nil || !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("NewProvider(freya-dns) = %v %v", p, err)
	}
	// Other providers behave as before through the injected variant.
	if p, err := NewProviderWith("manual", nil, ProviderDeps{FreyaDNS: &fakeFreyaDNS{}, TenantID: issuerTenant}); err != nil {
		t.Fatal(err)
	} else if _, ok := p.(*NoopProvider); !ok {
		t.Fatalf("manual = %T", p)
	}
	if _, err := NewProviderWith("route53", map[string]string{"secret_access_key": "x"}, ProviderDeps{}); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("route53 = %v", err)
	}
}

func TestFreyaDNSErrorsAreOpaque(t *testing.T) {
	fake := &fakeFreyaDNS{err: errors.New("dns: zone example.com of tenant X: internal detail")}
	p, err := NewProviderWith(FreyaDNS, nil, ProviderDeps{FreyaDNS: fake, TenantID: issuerTenant})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []func() error{
		func() error {
			return p.Present(context.Background(), "example.com", "_acme-challenge.example.com", "v")
		},
		func() error {
			return p.CleanUp(context.Background(), "example.com", "_acme-challenge.example.com", "v")
		},
	} {
		err := op()
		if !errors.Is(err, ErrProvider) || strings.Contains(err.Error(), "internal detail") {
			t.Fatalf("error = %v", err)
		}
	}
}
