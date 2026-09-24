package revoke

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

const tenant = "11111111-1111-7111-8111-111111111111"

func TestTrustBundleFeedAndCRL(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	env, err := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	authority := ca.New(st, env)
	if _, err := authority.EnsureCA(ctx, tenant, "example.org"); err != nil {
		t.Fatalf("ensure ca: %v", err)
	}
	svc := New(st, authority, func() time.Time { return time.Unix(1700000000, 0) })

	// Trust bundle is non-empty PEM.
	b, err := svc.TrustBundle(ctx, tenant, "example.org")
	if err != nil || len(b) == 0 {
		t.Fatalf("bundle: %v len=%d", err, len(b))
	}

	// Record a revocation and check the feed + CRL.
	rev := store.Revocation{ID: store.NewID(), TenantID: tenant, CertificateID: store.NewID(), Serial: "123456789", Reason: "keyCompromise", RevokedAt: time.Unix(1699999999, 0)}
	if err := st.InsertRevocation(ctx, rev); err != nil {
		t.Fatal(err)
	}
	feed, err := svc.Feed(ctx, tenant, time.Time{}, 100)
	if err != nil || len(feed) != 1 || feed[0].Serial != "123456789" {
		t.Fatalf("feed: %v %+v", err, feed)
	}
	crlPEM, err := svc.CRL(ctx, tenant, "example.org")
	if err != nil {
		t.Fatalf("crl: %v", err)
	}
	blk, _ := pem.Decode(crlPEM)
	if blk == nil || blk.Type != "X509 CRL" {
		t.Fatalf("crl not PEM: %q", string(crlPEM))
	}
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.String() != "123456789" {
		t.Fatalf("crl entries: %+v", crl.RevokedCertificateEntries)
	}
}
