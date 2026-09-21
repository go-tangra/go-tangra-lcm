package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/ca"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/memstore"
	"github.com/go-freya/freya/services/lcm/internal/revoke"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

func newIssue(t *testing.T) (*issue.Service, *memstore.Mem, *ca.Authority, func() time.Time, *audit.Writer) {
	t.Helper()
	st := memstore.New()
	env, _ := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	az := authz.New(st)
	aw := audit.NewWriter(st, nil)
	t.Cleanup(aw.Close)
	clock := time.Unix(1700000000, 0)
	authority := ca.New(st, env)
	authority.Clock = func() time.Time { return clock }
	return issue.New(st, authority, env, az, aw, func() time.Time { return clock }), st, authority, func() time.Time { return clock }, aw
}

// TestUS1_FullLifecycle: from an empty tenant, the CA auto-generates, an SVID is
// issued and its bundle validates against the CA, then renew supersedes and
// revoke changes status.
func TestUS1_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	iss, _, authority, _, _ := newIssue(t)
	if _, err := iss.CreateIssuer(ctx, admin(), issue.IssuerInput{Name: "root", Type: "self_signed", TrustDomain: "example.org", IsDefault: true, Enabled: true}); err != nil {
		t.Fatalf("issuer (CA auto-gen): %v", err)
	}
	b, err := iss.Issue(ctx, admin(), issue.IssueInput{SpiffeID: "spiffe://example.org/svc/api", ValiditySeconds: 3600, DeliverKey: true})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// The issued certificate validates against the trust bundle.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(b.BundlePEM)) {
		t.Fatal("bundle is not valid PEM")
	}
	blk, _ := pem.Decode([]byte(b.CertPEM))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(1700000000, 0), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to the CA: %v", err)
	}
	_ = authority
	// Renew supersedes the original.
	if _, err := iss.Renew(ctx, admin(), b.Certificate.ID); err != nil {
		t.Fatalf("renew: %v", err)
	}
	// Revoke changes status.
	if err := iss.Revoke(ctx, admin(), b.Certificate.ID, "keyCompromise"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, err := iss.GetCertificate(ctx, admin(), b.Certificate.ID)
	if err != nil || got.Status != "revoked" {
		t.Fatalf("status = %q (err %v), want revoked", got.Status, err)
	}
}

// TestUS5_RevocationFeedCRLAudit: revoking a certificate surfaces it in the
// revocation feed and the signed CRL, and the audit trail records it.
func TestUS5_RevocationFeedCRLAudit(t *testing.T) {
	ctx := context.Background()
	iss, st, authority, _, aw := newIssue(t)
	if _, err := iss.CreateIssuer(ctx, admin(), issue.IssuerInput{Name: "root", Type: "self_signed", TrustDomain: "example.org", IsDefault: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	b, err := iss.Issue(ctx, admin(), issue.IssueInput{SpiffeID: "spiffe://example.org/svc/api", ValiditySeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Revoke(ctx, admin(), b.Certificate.ID, "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	rv := revoke.New(st, authority, func() time.Time { return time.Unix(1700003600, 0) })
	feed, err := rv.Feed(ctx, tenant, time.Time{}, 100)
	if err != nil || len(feed) != 1 {
		t.Fatalf("feed: %v n=%d", err, len(feed))
	}
	crl, err := rv.CRL(ctx, tenant, "example.org")
	if err != nil {
		t.Fatalf("crl: %v", err)
	}
	blk, _ := pem.Decode(crl)
	parsed, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil || len(parsed.RevokedCertificateEntries) != 1 {
		t.Fatalf("crl entries: %v", err)
	}
	// Audit recorded the revocation.
	aw.Flush(ctx)
	rows, err := st.QueryAudit(ctx, tenant, store.AuditFilter{EventType: "certificate_revoked", Limit: 10})
	if err != nil || len(rows) == 0 {
		t.Fatalf("audit revoke: %v n=%d", err, len(rows))
	}
}
