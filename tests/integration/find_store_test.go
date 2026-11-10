//go:build integration

// FindCertificates (lcm.v1.Certificates/Find, the deployer's Deploy dialog)
// runs in a tenant transaction against the real schema: only the tenant's
// live host certificates come back, exact names first, then the wildcard
// covering the name, then names containing it.
//
// Run: go test -tags integration -run FindStore ./tests/integration/
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

func TestFindStore_ByHostName(t *testing.T) {
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
	serial := 0
	insert := func(tid, subject, sans, spiffe, status string, notAfter time.Time) string {
		serial++
		id := store.NewID()
		c := store.IssuedCertificate{
			ID: id, TenantID: tid, IssuerID: issuers[tid], Kind: "generic", Serial: fmt.Sprintf("%x", serial), SpiffeID: spiffe,
			Subject: subject, SANs: []byte(sans), NotBefore: now.Add(-time.Hour), NotAfter: notAfter,
			FingerprintSHA256: fmt.Sprintf("%064x", serial), Status: status, CertPEM: "pem", Owner: "u1",
		}
		if err := db.InsertCertificate(ctx, c); err != nil {
			t.Fatalf("insert certificate: %v", err)
		}
		return id
	}
	later := now.Add(90 * 24 * time.Hour)
	wild := insert(tenant, "*.infra.example.org", `["*.infra.example.org","infra.example.org"]`, "", "active", later.Add(time.Hour))
	exact := insert(tenant, "PBX.infra.example.org", `["pbx.infra.example.org"]`, "", "active", later)
	partial := insert(tenant, "pbx2.infra.example.org", `["pbx2.infra.example.org"]`, "", "expiring", later)
	insert(tenant, "pbx.infra.example.org", `["pbx.infra.example.org"]`, "", "active", now.Add(-time.Minute)) // expired
	insert(tenant, "pbx.infra.example.org", `["pbx.infra.example.org"]`, "", "revoked", later)                // not live
	insert(tenant, "spiffe://infra.example.org/svc/pbx", `[]`, "spiffe://infra.example.org/svc/pbx", "active", later)
	superseded := insert(tenant, "pbx.infra.example.org", `["pbx.infra.example.org"]`, "", "active", later)
	if err := db.SetCertificateStatus(ctx, tenant, superseded, "active", &exact); err != nil {
		t.Fatal(err)
	}
	insert(other, "pbx.infra.example.org", `["pbx.infra.example.org"]`, "", "active", later)

	for _, tc := range []struct {
		name, wildcard string
		want           []string
	}{
		{"pbx.infra.example.org", "*.infra.example.org", []string{exact, wild}},
		{"pbx", "", []string{exact, partial}},
		{"web.infra.example.org", "*.infra.example.org", []string{wild}},
		{"nothing.example.com", "*.example.com", nil},
	} {
		got, err := db.FindCertificates(ctx, tenant, tc.name, tc.wildcard, now, 20)
		if err != nil {
			t.Fatalf("find %q: %v", tc.name, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("find %q: %d rows, want %d", tc.name, len(got), len(tc.want))
		}
		for i, c := range got {
			if c.ID != tc.want[i] || c.TenantID != tenant {
				t.Fatalf("find %q row %d = %s, want %s", tc.name, i, c.ID, tc.want[i])
			}
		}
	}
	if got, err := db.FindCertificates(ctx, tenant, "pbx", "", now, 1); err != nil || len(got) != 1 || got[0].ID != exact {
		t.Fatalf("limited = %+v, %v", got, err)
	}
}
