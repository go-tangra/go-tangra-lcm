package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// The legacy Audit page sent no limit: the listing must still return rows (a zero
// limit reached SQL as LIMIT 0), bounded by the default and the maximum.
func TestAuditListingDefaultsTheLimit(t *testing.T) {
	f := newAPI(t)
	now := time.Now().UTC()
	rows := make([]store.AuditRow, 0, 600)
	for i := range 600 {
		rows = append(rows, store.AuditRow{TS: now.Add(-time.Duration(i) * time.Second), TenantID: apiTenant, EventType: "issuer_created",
			ActorKind: "user", ActorID: apiAdmin, SubjectKind: "issuer", SubjectID: fmt.Sprint(i), Outcome: "ok", Details: []byte(`{}`)})
	}
	if err := f.mem.InsertAuditRows(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	count := func(path string) int {
		t.Helper()
		w := f.req(t, "GET", Prefix+path, "admin", "")
		mustStatus(t, w, http.StatusOK)
		items, _ := jsonBody(t, w)["items"].([]any)
		return len(items)
	}
	// No parameters: the list contract's default page (store.AuditList).
	if n := count("/audit"); n != store.AuditList.DefaultSize {
		t.Fatalf("no params: %d rows, want %d", n, store.AuditList.DefaultSize)
	}
	// The legacy cursor path without a limit keeps its default.
	if n := count("/audit?cursor="); n != store.DefaultAuditLimit {
		t.Fatalf("legacy without limit: %d rows, want %d", n, store.DefaultAuditLimit)
	}
	if n := count("/audit?limit=10"); n != 10 {
		t.Fatalf("limit=10: %d rows", n)
	}
	if n := count("/audit?limit=100000"); n != store.MaxAuditLimit {
		t.Fatalf("limit above max: %d rows, want %d", n, store.MaxAuditLimit)
	}
}
