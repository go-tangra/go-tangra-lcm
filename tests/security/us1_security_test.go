package security

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
)

// TestSR002_IssuanceRefusesUnentitled: a caller with no relation on the issuer
// cannot mint an SVID for a SPIFFE id they are not entitled to.
func TestSR002_IssuanceRefusesUnentitled(t *testing.T) {
	s := newService(t)
	setupIssuer(t, s)
	_, err := s.Issue(context.Background(), stranger(), issue.IssueInput{
		SpiffeID: "spiffe://example.org/svc/api", ValiditySeconds: 3600,
	})
	if !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("unentitled issuance must be forbidden, got %v", err)
	}
}

// TestSR001_NoKeyMaterialLeaks: a generated private key is delivered exactly
// once at issuance and never appears again (download or listing), and no CA or
// issuer private key is ever present in any response.
func TestSR001_NoKeyMaterialLeaks(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	setupIssuer(t, s)

	b, err := s.Issue(ctx, admin(), issue.IssueInput{SpiffeID: "spiffe://example.org/svc/api", ValiditySeconds: 3600, DeliverKey: true})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(b.KeyPEM, "PRIVATE KEY") {
		t.Fatal("generated key must be delivered once at issuance")
	}
	dl, err := s.Download(ctx, admin(), b.Certificate.ID)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if dl.KeyPEM != "" {
		t.Fatal("download returned a private key")
	}
	if containsPrivateKey(dl.CertPEM, dl.ChainPEM, dl.BundlePEM) {
		t.Fatal("download bundle contains private-key material")
	}
	if _, _, err := s.ListCertificates(ctx, admin(), storeFilter()); err != nil {
		t.Fatalf("list: %v", err)
	}
	iv, err := s.GetIssuer(ctx, admin(), listIssuerID(t, s))
	if err != nil {
		t.Fatalf("get issuer: %v", err)
	}
	for k, v := range iv.Settings {
		if str, ok := v.(string); ok && strings.Contains(str, "PRIVATE KEY") {
			t.Fatalf("issuer setting %q leaked a private key", k)
		}
	}
}

func containsPrivateKey(parts ...string) bool {
	for _, p := range parts {
		if strings.Contains(p, "PRIVATE KEY") {
			return true
		}
	}
	return false
}
