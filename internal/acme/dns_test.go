package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProvidersRegistry(t *testing.T) {
	got := Providers()
	want := []string{
		"cloudflare", "route53", "gcloud", "digitalocean", "acmedns",
		"powerdns", "hurricane", "httpreq", "easydns", "manual", "freya-dns",
	}
	if len(got) != len(want) {
		t.Fatalf("Providers() returned %d entries, want %d", len(got), len(want))
	}
	byName := make(map[string]ProviderInfo, len(got))
	for _, p := range got {
		if p.DisplayName == "" {
			t.Errorf("provider %q has empty DisplayName", p.Name)
		}
		byName[p.Name] = p
	}
	for _, name := range want {
		if _, ok := byName[name]; !ok {
			t.Errorf("registry missing provider %q", name)
		}
	}

	// Every credential-based provider must advertise at least one required
	// secret field; manual and freya-dns (mesh identity) take none.
	for _, name := range want {
		if name == "manual" || name == "freya-dns" {
			if len(byName[name].Fields) != 0 {
				t.Errorf("%s provider should have no fields, got %d", name, len(byName[name].Fields))
			}
			continue
		}
		p := byName[name]
		var hasSecret bool
		for _, f := range p.Fields {
			if f.Key == "" || f.Label == "" {
				t.Errorf("provider %q has a field with empty key/label", name)
			}
			if f.Secret {
				hasSecret = true
			}
		}
		if !hasSecret {
			t.Errorf("provider %q advertises no secret field", name)
		}
	}
}

func TestProvidersIsCopy(t *testing.T) {
	a := Providers()
	if len(a) == 0 {
		t.Fatal("no providers")
	}
	a[0].DisplayName = "MUTATED"
	a[0].Fields = append(a[0].Fields, ProviderField{Key: "x"})
	b := Providers()
	if b[0].DisplayName == "MUTATED" {
		t.Error("Providers() leaks a mutable reference to the registry")
	}
}

func TestNewProviderManual(t *testing.T) {
	p, err := NewProvider("manual", map[string]string{"anything": "ignored"})
	if err != nil {
		t.Fatalf("NewProvider(manual): %v", err)
	}
	rec, ok := p.(*NoopProvider)
	if !ok {
		t.Fatalf("manual provider is %T, want *NoopProvider", p)
	}
	ctx := context.Background()
	if err := rec.Present(ctx, "example.com", "_acme-challenge.example.com", "v0"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := rec.CleanUp(ctx, "example.com", "_acme-challenge.example.com", "v0"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	calls := rec.Calls()
	if len(calls) != 2 || calls[0].Op != "present" || calls[1].Op != "cleanup" {
		t.Fatalf("unexpected recorded calls: %+v", calls)
	}
}

func TestNewProviderUnsupported(t *testing.T) {
	for _, name := range []string{"route53", "gcloud", "digitalocean", "unknown-xyz", "freya-dns"} {
		p, err := NewProvider(name, map[string]string{"api_token": "secret-value"})
		if p != nil {
			t.Errorf("NewProvider(%q) returned a non-nil provider", name)
		}
		if !errors.Is(err, ErrUnsupportedProvider) {
			t.Errorf("NewProvider(%q) error = %v, want ErrUnsupportedProvider", name, err)
		}
	}
}

func TestNewProviderNeverLeaksCredential(t *testing.T) {
	const secret = "super-secret-token-42"
	_, err := NewProvider("route53", map[string]string{"secret_access_key": secret})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error string leaked the credential value: %q", err.Error())
	}

	// Over-large values are rejected as data without echoing them.
	big := strings.Repeat("x", MaxCredValueBytes+1)
	_, err = NewProvider("manual", map[string]string{"blob": big})
	if err == nil || strings.Contains(err.Error(), big) {
		t.Fatalf("over-large credential mishandled: err=%v", err)
	}
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("over-large credential error = %v, want ErrProvider", err)
	}
}

func TestNoopProviderConcurrent(t *testing.T) {
	var p NoopProvider
	ctx := context.Background()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			_ = p.Present(ctx, "d", "f", "v")
			_ = p.CleanUp(ctx, "d", "f", "v")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if len(p.Calls()) != 16 {
		t.Fatalf("recorded %d calls, want 16", len(p.Calls()))
	}
}
