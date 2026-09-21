package stats

import (
	"context"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/memstore"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

type fakeHub struct{ n int }

func (h fakeHub) OpenStreams() int { return h.n }

func TestTenantStats(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	tenant := "11111111-1111-7111-8111-111111111111"
	iss := store.Issuer{ID: store.NewID(), TenantID: tenant, Name: "i", Type: "self_signed", TrustDomain: "example.org", Enabled: true}
	if err := st.InsertIssuer(ctx, iss); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	c := store.IssuedCertificate{ID: store.NewID(), TenantID: tenant, IssuerID: iss.ID, Serial: "1", SpiffeID: "spiffe://example.org/svc/a", Status: "active", CertPEM: "x", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	if err := st.InsertCertificate(ctx, c); err != nil {
		t.Fatal(err)
	}
	svc := New(st, fakeHub{n: 3}, 24*time.Hour, func() time.Time { return now })
	v, err := svc.Tenant(ctx, tenant)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if v.Issuers != 1 {
		t.Errorf("issuers = %d, want 1", v.Issuers)
	}
	if v.Certificates["active"] != 1 {
		t.Errorf("active certs = %d, want 1", v.Certificates["active"])
	}
	if v.OpenStreams != 3 {
		t.Errorf("open_streams = %d, want 3", v.OpenStreams)
	}
}
