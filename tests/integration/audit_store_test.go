//go:build integration

// The audit listing on a real TimescaleDB: the Audit page sends no limit, and
// a zero limit must not reach SQL as LIMIT 0.
//
// Run: go test -tags integration -run AuditStore ./tests/integration/
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

// QueryAudit on Postgres: a zero limit (no ?limit from the Audit page) must
// not become LIMIT 0.
func TestAuditStore_ZeroLimitReturnsRows(t *testing.T) {
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
	now := time.Now().UTC()
	rows := make([]store.AuditRow, 0, 3)
	for i := range 3 {
		rows = append(rows, store.AuditRow{TS: now.Add(-time.Duration(i) * time.Second), TenantID: tenant, EventType: "issuer_created",
			ActorKind: "user", ActorID: "u1", SubjectKind: "issuer", SubjectID: fmt.Sprint(i), Outcome: "ok", Details: []byte(`{}`)})
	}
	if err := db.InsertAuditRows(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, err := db.QueryAudit(ctx, tenant, store.AuditFilter{})
	if err != nil || len(got) != 3 {
		t.Fatalf("zero limit: %d rows, %v", len(got), err)
	}
	if got, err := db.QueryAudit(ctx, tenant, store.AuditFilter{Limit: 2}); err != nil || len(got) != 2 {
		t.Fatalf("limit 2: %d rows, %v", len(got), err)
	}
}
