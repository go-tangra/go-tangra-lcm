package enroll

// ACME orders recorded by the issue service appear on the requests listing as
// generic requests and cannot be approved or rejected.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
)

func TestACMEOrdersListedAsGenericRequests(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	ctx := context.Background()
	iv, err := f.iss.CreateIssuer(ctx, f.admin, issue.IssuerInput{
		Name: "le", Type: "acme", TrustDomain: "example.org", Enabled: true,
		ACMEDirectoryURL: "https://127.0.0.1:1/dir", ACMEEmail: "ops@example.org", DNSProvider: "cloudflare",
		Settings: sealed.Settings{"api_token": "t", "zone_id": "z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := f.iss.BeginACME(ctx, f.admin, iv.ID, []string{"*.example.org", "example.org"})
	if err != nil {
		t.Fatal(err)
	}
	bad, err := f.iss.BeginACME(ctx, f.admin, iv.ID, []string{"www.example.org"})
	if err != nil {
		t.Fatal(err)
	}

	items, _, err := f.svc.ListRequests(ctx, f.admin, RequestFilter{Status: "processing"})
	if err != nil || len(items) != 2 {
		t.Fatalf("processing = %+v, %v", items, err)
	}
	for _, v := range items {
		if v.Kind != "generic" || v.SpiffeID != "" || v.Status != "processing" || v.IssuerID != iv.ID || len(v.SANs) == 0 {
			t.Fatalf("view = %+v", v)
		}
	}

	// Only pending requests are approved or rejected.
	var ce *ConflictError
	if _, err := f.svc.ApproveRequest(ctx, f.admin, ok.RequestID, ""); !errors.As(err, &ce) {
		t.Fatalf("approve processing: want ConflictError, got %v", err)
	}
	if _, err := f.svc.RejectRequest(ctx, f.admin, ok.RequestID, ""); !errors.As(err, &ce) {
		t.Fatalf("reject processing: want ConflictError, got %v", err)
	}

	if err := f.iss.FinishACME(ctx, f.admin, ok.RequestID, "cert-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.iss.FinishACME(ctx, f.admin, bad.RequestID, "", errors.New("acme: order failed: rejected")); err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.GetRequest(ctx, f.admin, ok.RequestID)
	if err != nil || v.Status != "issued" || v.CertificateID != "cert-1" || strings.Join(v.SANs, ",") != "*.example.org,example.org" {
		t.Fatalf("issued view = %+v, %v", v, err)
	}
	failed, _, err := f.svc.ListRequests(ctx, f.admin, RequestFilter{Status: "failed"})
	if err != nil || len(failed) != 1 || failed[0].ID != bad.RequestID || failed[0].Reason != "acme: order failed: rejected" || failed[0].CertificateID != "" {
		t.Fatalf("failed = %+v, %v", failed, err)
	}
	if _, err := f.svc.ApproveRequest(ctx, f.admin, bad.RequestID, ""); !errors.As(err, &ce) {
		t.Fatalf("approve failed: want ConflictError, got %v", err)
	}

	// An svid request still reads as kind svid.
	f.mustIssuer(t)
	res, err := f.svc.Enroll(ctx, f.admin, EnrollInput{SpiffeID: "spiffe://example.org/x"})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := f.svc.GetRequest(ctx, f.admin, res.RequestID); err != nil || v.Kind != "svid" {
		t.Fatalf("svid view = %+v, %v", v, err)
	}
}
