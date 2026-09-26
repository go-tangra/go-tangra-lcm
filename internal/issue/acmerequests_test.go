package issue

// ACME orders are validated before any network call and recorded as generic
// certificate requests that run processing -> issued|failed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
)

func TestValidateACMEDomainsAccepts(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"Example.ORG."}, []string{"example.org"}},
		{[]string{" www.example.org ", "WWW.example.org", "www.example.org."}, []string{"www.example.org"}},
		{[]string{"*.example.org", "example.org"}, []string{"*.example.org", "example.org"}},
		{[]string{"*.server-lab.eu", "a.test.server-lab.eu"}, []string{"*.server-lab.eu", "a.test.server-lab.eu"}},
		{[]string{"xn--bcher-kva.example", "a-b.c1.io", ""}, []string{"xn--bcher-kva.example", "a-b.c1.io"}},
	}
	for _, c := range cases {
		got, err := validateACMEDomains(c.in)
		if err != nil {
			t.Fatalf("%v: %v", c.in, err)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("%v: got %v want %v", c.in, got, c.want)
		}
	}
}

func TestValidateACMEDomainsRefuses(t *testing.T) {
	long63 := strings.Repeat("a", 63)
	tooMany := make([]string, 101)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("h%d.example.org", i)
	}
	cases := []struct {
		name  string
		in    []string
		names string // substring the message must carry
	}{
		{"empty", []string{" ", ""}, "at least one"},
		{"leading hyphen label", []string{"*.server.-lab.eu"}, "*.server.-lab.eu"},
		{"trailing hyphen label", []string{"server-.lab.eu"}, "server-.lab.eu"},
		{"single label", []string{"localhost"}, "localhost"},
		{"empty label", []string{"a..example.org"}, "a..example.org"},
		{"nested wildcard", []string{"*.*.example.org"}, "*.*.example.org"},
		{"inner wildcard", []string{"www.*.example.org"}, "www.*.example.org"},
		{"bare wildcard tld", []string{"*.org"}, "*.org"},
		{"underscore", []string{"a_b.example.org"}, "a_b.example.org"},
		{"label too long", []string{long63 + "a.example.org"}, long63},
		{"name too long", []string{strings.Repeat(long63+".", 4) + "org"}, "253"},
		{"too many", tooMany, "100"},
		{"redundant with wildcard", []string{"*.server-lab.eu", "test.server-lab.eu"}, "test.server-lab.eu"},
		{"redundant before wildcard", []string{"Test.Server-Lab.eu", "*.server-lab.eu"}, "test.server-lab.eu"},
	}
	for _, c := range cases {
		_, err := validateACMEDomains(c.in)
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Field != "domains" {
			t.Fatalf("%s: want domains ValidationError, got %v", c.name, err)
		}
		if !strings.Contains(ve.Message, c.names) {
			t.Fatalf("%s: message %q does not name %q", c.name, ve.Message, c.names)
		}
	}
}

func TestBeginACMERecordsProcessingRequest(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	iv := cloudflareIssuer(t, f)
	order, err := f.svc.BeginACME(ctx, f.admin, iv.ID, []string{"*.Example.org", "example.org."})
	if err != nil {
		t.Fatal(err)
	}
	if order.RequestID == "" || strings.Join(order.Domains, ",") != "*.example.org,example.org" {
		t.Fatalf("order = %+v", order)
	}
	r, ok := f.mem.Requests[order.RequestID]
	if !ok {
		t.Fatal("request not stored")
	}
	var sans []string
	_ = json.Unmarshal(r.SANs, &sans)
	if r.Kind != "generic" || r.SpiffeID != "" || r.Status != "processing" || r.IssuerID == nil || *r.IssuerID != iv.ID ||
		r.RequestedBy != "u-admin" || r.RequesterKind != "user" || strings.Join(sans, ",") != "*.example.org,example.org" {
		t.Fatalf("request row = %+v", r)
	}
	var found bool
	for _, a := range f.audits(t) {
		if a.EventType == string(audit.CertificateRequested) && a.SubjectID == order.RequestID {
			found = a.Outcome == audit.OutcomeOK
		}
	}
	if !found {
		t.Fatal("certificate_requested not audited")
	}

	// A service caller is recorded as such.
	svc := authz.Subjects{TenantID: "t1", Service: "spiffe://example.org/svc", Roles: []string{"admin"}}
	o2, err := f.svc.BeginACME(ctx, svc, iv.ID, []string{"api.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if r := f.mem.Requests[o2.RequestID]; r.RequesterKind != "service" || r.RequestedBy != "spiffe://example.org/svc" {
		t.Fatalf("service request row = %+v", r)
	}
}

func TestBeginACMERefusesBeforeRecording(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	iv := cloudflareIssuer(t, f)
	var ve *ValidationError
	if _, err := f.svc.BeginACME(ctx, f.admin, iv.ID, []string{"*.server-lab.eu", "test.server-lab.eu"}); !errors.As(err, &ve) || ve.Field != "domains" {
		t.Fatalf("redundant domains: %v", err)
	}
	if _, err := f.svc.BeginACME(ctx, f.admin, "0000", []string{"example.org"}); !errors.As(err, &ve) || ve.Field != "issuer_id" {
		t.Fatalf("unknown issuer: %v", err)
	}
	stranger := authz.Subjects{TenantID: "t1", UserID: "u-stranger"}
	if _, err := f.svc.BeginACME(ctx, stranger, iv.ID, []string{"example.org"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("stranger: %v", err)
	}
	if n := len(f.mem.Requests); n != 0 {
		t.Fatalf("%d requests recorded for refused orders", n)
	}
}

func TestFinishACME(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	iv := cloudflareIssuer(t, f)
	ok, err := f.svc.BeginACME(ctx, f.admin, iv.ID, []string{"example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.FinishACME(ctx, f.admin, ok.RequestID, "cert-1", nil); err != nil {
		t.Fatal(err)
	}
	if r := f.mem.Requests[ok.RequestID]; r.Status != "issued" || r.CertificateID == nil || *r.CertificateID != "cert-1" || r.Reason != nil {
		t.Fatalf("issued row = %+v", r)
	}

	bad, err := f.svc.BeginACME(ctx, f.admin, iv.ID, []string{"www.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("acme: order failed\n" + strings.Repeat("x", 2000))
	if err := f.svc.FinishACME(ctx, f.admin, bad.RequestID, "", cause); err != nil {
		t.Fatal(err)
	}
	r := f.mem.Requests[bad.RequestID]
	if r.Status != "failed" || r.CertificateID != nil || r.Reason == nil {
		t.Fatalf("failed row = %+v", r)
	}
	if *r.Reason != FailReason(cause) || strings.Contains(*r.Reason, "\n") || len(*r.Reason) > 600 {
		t.Fatalf("reason = %q", *r.Reason)
	}
}

// A failed order ends the request failed with the order's reason (the
// provider cannot be built here, so no network call is made).
func TestObtainACMEForRequestLinksOutcome(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	iv, err := f.svc.CreateIssuer(ctx, f.admin, IssuerInput{
		Name: "le", Type: "acme", TrustDomain: "example.org", Enabled: true,
		ACMEDirectoryURL: "https://127.0.0.1:1/dir", ACMEEmail: "ops@example.org", DNSProvider: "cloudflare",
		Settings: map[string]any{"zone_id": "z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	order, err := f.svc.BeginACME(ctx, f.admin, iv.ID, []string{"www.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	b, oerr := f.svc.ObtainACMEFor(ctx, f.admin, order.RequestID, iv.ID, order.Domains, "", false, true)
	if oerr == nil {
		t.Fatal("want error")
	}
	if err := f.svc.FinishACME(ctx, f.admin, order.RequestID, b.Certificate.ID, oerr); err != nil {
		t.Fatal(err)
	}
	if r := f.mem.Requests[order.RequestID]; r.Status != "failed" || r.Reason == nil || *r.Reason == "" {
		t.Fatalf("request row = %+v", r)
	}
}
