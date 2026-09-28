//go:build integration

// ExpiringCertificates (feature 026, lcm:check-expiring-certificates) runs in a
// tenant transaction against the real schema: only the tenant's live, not yet
// expired, not superseded certificates within the horizon come back, soonest
// first and bounded by the limit.
//
// Run: go test -tags integration -run ExpiringStore ./tests/integration/
// (needs Docker; skips cleanly without it).
package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

func TestExpiringStore_TenantScopedHorizon(t *testing.T) {
	ctx := context.Background()
	dsn := startTimescale(t, ctx)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := store.Open(ctx, dsn, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := repodb.New(st)

	const other = "33333333-3333-7333-8333-333333333333"
	issuers := map[string]string{}
	for _, tid := range []string{tenant, other} {
		id := store.NewID()
		if err := db.InsertIssuer(ctx, store.Issuer{ID: id, TenantID: tid, Name: "root", Type: "self_signed", TrustDomain: "example.org", Enabled: true}); err != nil {
			t.Fatalf("issuer: %v", err)
		}
		issuers[tid] = id
	}

	now := time.Now().UTC().Truncate(time.Second)
	before := now.Add(7 * 24 * time.Hour)
	serial := 0
	insert := func(tid, status string, notAfter time.Time) string {
		serial++
		id := store.NewID()
		c := store.IssuedCertificate{
			ID: id, TenantID: tid, IssuerID: issuers[tid], Kind: "generic", Serial: fmt.Sprintf("%x", serial),
			Subject: "CN=host", SANs: []byte(`["host.example.org"]`), NotBefore: now.Add(-24 * time.Hour), NotAfter: notAfter,
			FingerprintSHA256: fmt.Sprintf("%064x", serial), Status: status, CertPEM: "pem", Owner: "u1",
		}
		if err := db.InsertCertificate(ctx, c); err != nil {
			t.Fatalf("insert certificate: %v", err)
		}
		return id
	}
	third := insert(tenant, "active", now.Add(72*time.Hour))
	first := insert(tenant, "expiring", now.Add(time.Hour))
	second := insert(tenant, "active", now.Add(24*time.Hour))
	insert(tenant, "active", now.Add(-time.Hour))                // already expired
	insert(tenant, "active", before.Add(time.Hour))              // outside the horizon
	insert(tenant, "revoked", now.Add(time.Hour))                // not live
	superseded := insert(tenant, "active", now.Add(2*time.Hour)) // replaced below
	if err := db.SetCertificateStatus(ctx, tenant, superseded, "active", &second); err != nil {
		t.Fatal(err)
	}
	foreign := insert(other, "active", now.Add(time.Hour))

	got, err := db.ExpiringCertificates(ctx, tenant, now, before, 100)
	if err != nil {
		t.Fatalf("expiring: %v", err)
	}
	want := []string{first, second, third}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.ID != want[i] || c.TenantID != tenant {
			t.Fatalf("row %d = %s (%s), want %s", i, c.ID, c.TenantID, want[i])
		}
	}
	if string(got[0].SANs) == "" || got[0].IssuerID != issuers[tenant] {
		t.Fatalf("row columns = %+v", got[0])
	}

	// Bounded.
	if got, err := db.ExpiringCertificates(ctx, tenant, now, before, 1); err != nil || len(got) != 1 || got[0].ID != first {
		t.Fatalf("limited = %+v, %v", got, err)
	}
	// The other tenant sees only its own certificate.
	if got, err := db.ExpiringCertificates(ctx, other, now, before, 100); err != nil || len(got) != 1 || got[0].ID != foreign {
		t.Fatalf("other tenant = %+v, %v", got, err)
	}
}
