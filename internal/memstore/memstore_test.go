package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

const (
	tenantA = "11111111-1111-7111-8111-111111111111"
	tenantB = "22222222-2222-7222-8222-222222222222"
)

// TestExpiringCertificates: tenant-scoped, live (active/expiring, not
// superseded), not yet expired and within the horizon, soonest first, bounded.
func TestExpiringCertificates(t *testing.T) {
	m := New()
	now := time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC)
	before := now.Add(7 * 24 * time.Hour)
	sup := "superseding"
	add := func(id, tenant, status string, notAfter time.Time, supersededBy *string) {
		m.Certificates[id] = store.IssuedCertificate{ID: id, TenantID: tenant, Status: status, NotAfter: notAfter, SupersededBy: supersededBy, SANs: []byte(`["a"]`)}
	}
	add("c3", tenantA, "active", now.Add(72*time.Hour), nil)
	add("c1", tenantA, "expiring", now.Add(time.Hour), nil)
	add("c2", tenantA, "active", now.Add(24*time.Hour), nil)
	add("edge", tenantA, "active", before, nil)                    // inclusive upper bound
	add("expired", tenantA, "active", now, nil)                    // not_after > now is required
	add("later", tenantA, "active", before.Add(time.Second), nil)  // outside the horizon
	add("revoked", tenantA, "revoked", now.Add(time.Hour), nil)    // not live
	add("superseded", tenantA, "active", now.Add(time.Hour), &sup) // replaced already
	add("foreign", tenantB, "active", now.Add(time.Hour), nil)     // another tenant

	got, err := m.ExpiringCertificates(context.Background(), tenantA, now, before, 100)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range got {
		ids = append(ids, c.ID)
	}
	want := []string{"c1", "c2", "c3", "edge"}
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %v, want %v", ids, want)
		}
	}
	// Rows are copies: mutating the result does not touch the store.
	got[0].SANs[0] = 'x'
	if m.Certificates["c1"].SANs[0] != '[' {
		t.Fatal("result aliases the stored row")
	}

	// Ties on not_after order by id; the limit bounds the result.
	add("c0", tenantA, "active", now.Add(time.Hour), nil)
	got, _ = m.ExpiringCertificates(context.Background(), tenantA, now, before, 2)
	if len(got) != 2 || got[0].ID != "c0" || got[1].ID != "c1" {
		t.Fatalf("limited = %+v", got)
	}
	if got, _ := m.ExpiringCertificates(context.Background(), tenantA, now, before, 0); len(got) != 0 {
		t.Fatalf("limit 0 = %+v", got)
	}

	// Another tenant sees only its own row.
	if got, _ := m.ExpiringCertificates(context.Background(), tenantB, now, before, 10); len(got) != 1 || got[0].ID != "foreign" {
		t.Fatalf("tenant B = %+v", got)
	}

	// Failure injection.
	boom := errors.New("boom")
	m.FailOn("ExpiringCertificates", boom)
	if _, err := m.ExpiringCertificates(context.Background(), tenantA, now, before, 10); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}
