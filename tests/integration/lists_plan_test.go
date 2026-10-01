//go:build integration

// Server-side tables performance (go-tangra specs/032-server-side-tables
// perf.md): with NotNull sort fields and the 0010 (tenant_id, created_at, id)
// index, the default certificate page (created_at desc) is an index scan
// without a Sort of the table, the deep page sorts and skips only ids (no
// wide cert_pem rows), and the issuer filter is index-backed.
//
// LCM_PLAN_ROWS (default 20000) sets the seeded certificate count; the test
// logs EXPLAIN ANALYZE timings of the page queries next to the pre-032-perf
// query shape (wide rows, NULLS LAST, correlated issuer subquery);
// LCM_PLAN_DUMP=1 logs the full plans.
package integration

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

func TestListsPlan_CertificatePagesUseIndexes(t *testing.T) {
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
	rows := 20000
	if v, err := strconv.Atoi(os.Getenv("LCM_PLAN_ROWS")); err == nil && v > 0 {
		rows = v
	}
	var issuers []string
	for _, tid := range []string{tenant, listOther} {
		for i := range 20 {
			id := store.NewID()
			if err := db.InsertIssuer(ctx, store.Issuer{ID: id, TenantID: tid, Name: "issuer-" + strconv.Itoa(i), Type: "self_signed", TrustDomain: "a.example", Enabled: true}); err != nil {
				t.Fatal(err)
			}
			if tid == tenant {
				issuers = append(issuers, id)
			}
		}
	}
	// Seed as the system scope: rows/issuers of the tenant, ~850 B of PEM each,
	// spread over a year; the other tenant gets a quarter as many.
	if err := st.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO issued_certificates (id, tenant_id, issuer_id, serial, spiffe_id, not_before, not_after, status, cert_pem, created_at)
			SELECT gen_random_uuid(), t.tid, (SELECT i.id FROM issuers i WHERE i.tenant_id = t.tid ORDER BY i.id OFFSET g % 20 LIMIT 1),
			       'serial-' || g, 'spiffe://a.example/svc-' || g, now() - (g || ' minutes')::interval,
			       now() + ((g % 9000) || ' hours')::interval, (ARRAY['active','expiring','expired','revoked'])[1 + g % 4],
			       repeat('x', 850), now() - ((random() * 525600)::int || ' minutes')::interval
			FROM generate_series(1, $1) g, (VALUES ($2::uuid, 1), ($3::uuid, 4)) AS t(tid, div)
			WHERE g % t.div = 0`, rows, tenant, listOther)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// VACUUM (outside a transaction) sets the visibility map as autovacuum
	// would, so the id-only scans stay index-only.
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "VACUUM ANALYZE issued_certificates"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "VACUUM ANALYZE issuers"); err != nil {
		t.Fatal(err)
	}
	lastPage := (rows + 49) / 50
	explain := func(analyze bool, sql string, args ...any) string {
		t.Helper()
		var out []string
		opts := "COSTS OFF"
		if analyze {
			opts = "ANALYZE, BUFFERS, COSTS OFF"
		}
		if err := st.Tx(ctx, store.Scope{TenantID: tenant}, func(tx pgx.Tx) error {
			r, err := tx.Query(ctx, "EXPLAIN ("+opts+") "+sql, args...)
			if err != nil {
				return err
			}
			defer r.Close()
			for r.Next() {
				var line string
				if err := r.Scan(&line); err != nil {
					return err
				}
				out = append(out, line)
			}
			return r.Err()
		}); err != nil {
			t.Fatalf("explain %s: %v", sql, err)
		}
		return strings.Join(out, "\n")
	}
	execTime := func(plan string) string {
		for _, l := range strings.Split(plan, "\n") {
			if strings.Contains(l, "Execution Time") {
				return strings.TrimSpace(l)
			}
		}
		return "?"
	}
	all := store.CertificatePageFilter{Visible: store.Visible{All: true}}
	for _, c := range []struct {
		name  string
		f     store.CertificatePageFilter
		req   listquery.Request
		index string
	}{
		{"default p1", all, listquery.Request{}, "certs_tenant_created"},
		{"created_at asc p1", all, listquery.Request{Sort: "created_at", Order: listquery.Asc}, "certs_tenant_created"},
		{"not_after desc p1", all, listquery.Request{Sort: "not_after", Order: listquery.Desc}, "certs_tenant_not_after"},
		{"deep default", all, listquery.Request{Page: lastPage, PageSize: 50}, "certs_tenant_created"},
		{"issuer filter p1", store.CertificatePageFilter{IssuerID: issuers[3], Visible: store.Visible{All: true}}, listquery.Request{}, "certs_tenant_issuer_created"},
	} {
		sql, args := store.CertificatePageSQL(tenant, c.f, c.req)
		plan := explain(false, sql, args...)
		if !strings.Contains(plan, c.index) {
			t.Errorf("%s: %s not used:\n%s", c.name, c.index, plan)
		}
		// The only Sort left orders the page's ids by position.
		for _, l := range strings.Split(plan, "\n") {
			if strings.Contains(l, "Sort Key") && !strings.Contains(l, "page_ids.pos") {
				t.Errorf("%s sorts the table (%s):\n%s", c.name, strings.TrimSpace(l), plan)
			}
		}
		analyzed := explain(true, sql, args...)
		if os.Getenv("LCM_PLAN_DUMP") != "" {
			t.Logf("%s:\n%s", c.name, analyzed)
		}
		t.Logf("%s: %s", c.name, execTime(analyzed))
	}
	// Issuer sort (admin): a join, no per-row subquery; deep page logged.
	sql, args := store.CertificatePageSQL(tenant, all, listquery.Request{Sort: "issuer", Page: lastPage, PageSize: 50})
	plan := explain(true, sql, args...)
	if strings.Contains(plan, "SubPlan") {
		t.Errorf("issuer sort runs a subquery per row:\n%s", plan)
	}
	t.Logf("deep issuer asc: %s", execTime(plan))
	// The pre-032-perf shapes, for comparison.
	off := (lastPage - 1) * 50
	for name, q := range map[string]string{
		"old default p1":       "SELECT * FROM issued_certificates c WHERE c.tenant_id = $1 ORDER BY c.created_at DESC NULLS LAST, c.id DESC LIMIT 25",
		"old deep default":     "SELECT * FROM issued_certificates c WHERE c.tenant_id = $1 ORDER BY c.created_at DESC NULLS LAST, c.id DESC LIMIT 50 OFFSET " + strconv.Itoa(off),
		"old deep issuer asc":  "SELECT * FROM issued_certificates c WHERE c.tenant_id = $1 ORDER BY lower((SELECT i.name FROM issuers i WHERE i.tenant_id = c.tenant_id AND i.id = c.issuer_id)) ASC NULLS LAST, c.id ASC LIMIT 50 OFFSET " + strconv.Itoa(off),
		"old issuer filter p1": "SELECT * FROM issued_certificates c WHERE c.tenant_id = $1 AND c.issuer_id::text = '" + issuers[3] + "' ORDER BY c.created_at DESC NULLS LAST, c.id DESC LIMIT 25",
	} {
		t.Logf("%s: %s", name, execTime(explain(true, q, tenant)))
	}
}
