package issue

// DNS-provider credentials entered in the issuer form (flat settings keys such
// as api_token) are sealed, redacted on every read, kept across edits and fed
// to the provider; issuers for providers without an adapter are refused; a
// failed ACME order is audited.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/acme"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
)

const cfToken = "cf-token-must-stay-sealed"

func cloudflareIssuer(t *testing.T, f *fixture) IssuerView {
	t.Helper()
	iv, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "le", Type: "acme", TrustDomain: "example.org", Enabled: true,
		ACMEDirectoryURL: "https://127.0.0.1:1/dir", ACMEEmail: "ops@example.org", DNSProvider: "cloudflare",
		Settings: sealed.Settings{"dns_provider": "cloudflare", "api_token": cfToken, "zone_id": "zone-1"},
	})
	if err != nil {
		t.Fatalf("CreateIssuer: %v", err)
	}
	return iv
}

func TestProviderSecretsSealedAndRedacted(t *testing.T) {
	f := newFixture(t)
	iv := cloudflareIssuer(t, f)
	if iv.Settings["api_token"] != sealed.Marker || iv.Settings["zone_id"] != "zone-1" {
		t.Fatalf("view settings = %v", iv.Settings)
	}
	row := f.mem.Issuers[iv.ID]
	if bytes.Contains(row.SettingsPublic, []byte(cfToken)) {
		t.Fatalf("token stored in public settings: %s", row.SettingsPublic)
	}
	blob, _ := json.Marshal(iv)
	if bytes.Contains(blob, []byte(cfToken)) {
		t.Fatal("token in issuer view")
	}
	got, err := f.svc.GetIssuer(context.Background(), f.admin, iv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Settings["api_token"] != sealed.Marker {
		t.Fatalf("read settings = %v", got.Settings)
	}
}

func TestProviderSecretKeptAcrossEdit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	iv := cloudflareIssuer(t, f)
	// The form sends the marker back for an untouched secret.
	if _, err := f.svc.UpdateIssuer(ctx, f.admin, iv.ID, IssuerInput{Name: "le2", Enabled: true, DNSProvider: "cloudflare",
		ACMEDirectoryURL: "https://127.0.0.1:1/dir", ACMEEmail: "ops@example.org",
		Settings: sealed.Settings{"dns_provider": "cloudflare", "api_token": sealed.Marker, "zone_id": "zone-2"}}); err != nil {
		t.Fatal(err)
	}
	issuer, err := f.mem.GetIssuer(ctx, f.admin.TenantID, iv.ID)
	if err != nil {
		t.Fatal(err)
	}
	settings := openSettings(t, f, issuer.ID, issuer.SettingsSealed)
	if settings["api_token"] != cfToken || settings["zone_id"] != "zone-2" {
		t.Fatalf("sealed settings = %v", settings)
	}
	creds := providerCreds(issuer.DNSProvider, settings)
	if creds["api_token"] != cfToken || creds["zone_id"] != "zone-2" {
		t.Fatalf("creds = %v", creds)
	}
	p, err := f.svc.dnsProvider(issuer, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(*acme.Cloudflare); !ok {
		t.Fatalf("provider = %T", p)
	}
}

func openSettings(t *testing.T, f *fixture, id string, blob []byte) sealed.Settings {
	t.Helper()
	clear, err := f.env.Open(blob, sealed.ADIssuer(id))
	if err != nil {
		t.Fatal(err)
	}
	s, err := sealed.Decode(clear)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestProviderCredsPreferNestedCredential(t *testing.T) {
	creds := providerCreds("cloudflare", sealed.Settings{
		"api_token":      "flat",
		"dns_credential": map[string]any{"api_token": "nested"},
		"directory":      "https://example",
	})
	if creds["api_token"] != "nested" {
		t.Fatalf("creds = %v", creds)
	}
	if _, ok := creds["directory"]; ok {
		t.Fatal("non-provider keys must not become credentials")
	}
}

func TestUnsupportedProviderRefused(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "r53", Type: "acme", TrustDomain: "example.org", Enabled: true, DNSProvider: "route53",
		Settings: sealed.Settings{"secret_access_key": "x"},
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "dns_provider" {
		t.Fatalf("want dns_provider ValidationError, got %v", err)
	}
}

func TestObtainACMEFailureAudited(t *testing.T) {
	f := newFixture(t)
	iv, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "le", Type: "acme", TrustDomain: "example.org", Enabled: true,
		ACMEDirectoryURL: "https://127.0.0.1:1/dir", ACMEEmail: "ops@example.org", DNSProvider: "cloudflare",
		Settings: sealed.Settings{"zone_id": "z"}, // no api_token: the provider cannot be built
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ObtainACME(context.Background(), f.admin, iv.ID, []string{"www.example.org"}, "", false, true); err == nil {
		t.Fatal("want error")
	}
	var found bool
	for _, a := range f.audits(t) {
		if a.EventType == string(audit.CertificateIssued) && a.Outcome == audit.OutcomeFailed {
			found = true
			if a.SubjectName != "www.example.org" || a.Reason == "" {
				t.Fatalf("audit row = %+v", a)
			}
		}
	}
	if !found {
		t.Fatal("failed ACME order not audited")
	}
}
