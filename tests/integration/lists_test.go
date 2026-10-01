//go:build integration

// Server-side tables (go-tangra specs/032-server-side-tables, wave C): the
// certificate, issuer, request, job, secret, webhook and audit pages run
// against a real TimescaleDB (migrations through 0010). For a user with
// partial grants every total and page equals the admin view filtered by the
// per-record read checks (the readable-ID set is part of the count and the
// page query); hidden records are never counted. The legacy certificate
// cursor continues instead of repeating page 1, the cursor reads behind
// SVIDServer.Verify are unchanged, and audit pages default to a 7-day window.
//
// Run: go test -tags integration -run Lists ./tests/integration/
// (needs Docker; skips cleanly without it).
package integration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/webhook"
)

const (
	listOther = "99999999-9999-7999-8999-999999999999"
	listBob   = "33333333-3333-7333-8333-333333333333"
	listCarol = "44444444-4444-7444-8444-444444444444"
)

type listEnv struct {
	db       *repodb.DB
	iss      *issue.Service
	enr      *enroll.Service
	sec      *secrets.Service
	hooks    *webhook.Service
	issuers  []string
	certs    []string
	requests []string
	jobs     []string
}

func bob() authz.Subjects { return authz.Subjects{TenantID: tenant, UserID: listBob} }

func newListEnv(t *testing.T) *listEnv {
	t.Helper()
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
	env, _ := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	az := authz.New(db)
	aw := audit.NewWriter(db, nil)
	t.Cleanup(aw.Close)
	iss := issue.New(db, ca.New(db, env), env, az, aw, nil)
	e := &listEnv{db: db, iss: iss, enr: enroll.New(db, iss, az, aw, rejectTokens{}, enroll.Config{}, nil),
		sec: secrets.New(db, env, aw, nil), hooks: webhook.New(db, env, aw, nil)}
	e.seed(t)
	return e
}

// seed: issuers A (default a.example), B (default b.example), C (a.example,
// not default); 30 certificates spread over them in creation-time pairs;
// requests and jobs covering every visibility rule; bob reads A and C and
// every third certificate. Another tenant mirrors some rows.
func (e *listEnv) seed(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, d := range []struct {
		tid, name, td string
		def           bool
	}{{tenant, "Alpha", "a.example", true}, {tenant, "Bravo", "b.example", true}, {tenant, "charlie", "a.example", false}, {listOther, "Alpha", "a.example", true}} {
		id := store.NewID()
		if err := e.db.InsertIssuer(ctx, store.Issuer{ID: id, TenantID: d.tid, Name: d.name, Type: "self_signed", TrustDomain: d.td, IsDefault: d.def, Enabled: true}); err != nil {
			t.Fatalf("issuer: %v", err)
		}
		if d.tid == tenant {
			e.issuers = append(e.issuers, id)
		}
	}
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for i := range 30 {
		id := store.NewID()
		created := base.Add(time.Duration(i/2) * time.Second)
		c := store.IssuedCertificate{ID: id, TenantID: tenant, IssuerID: e.issuers[i%3], Kind: "svid", Serial: fmt.Sprintf("s%02d", i),
			SpiffeID: fmt.Sprintf("spiffe://a.example/svc-%02d", 29-i), SANs: []byte(`[]`), NotBefore: created, NotAfter: created.Add(time.Duration(90-i) * time.Hour),
			Status: "active", CertPEM: "pem"}
		if err := e.db.InsertCertificate(ctx, c); err != nil {
			t.Fatalf("cert: %v", err)
		}
		// Pairs share a creation time (the id tie-breaker keeps pages stable).
		if err := e.db.St.Tx(ctx, store.Scope{TenantID: tenant}, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "UPDATE issued_certificates SET created_at = $2 WHERE id = $1", id, created)
			return err
		}); err != nil {
			t.Fatalf("created_at: %v", err)
		}
		e.certs = append(e.certs, id)
	}
	ptr := func(v string) *string { return &v }
	for i, d := range []struct {
		issuer *string
		spiffe string
		by     string
	}{
		{ptr(e.issuers[0]), "spiffe://a.example/p0", listCarol},
		{ptr(e.issuers[1]), "spiffe://b.example/p1", listCarol},
		{ptr(e.issuers[2]), "spiffe://a.example/p2", listCarol},
		{nil, "spiffe://a.example/u3", listCarol},
		{nil, "spiffe://b.example/u4", listCarol},
		{nil, "spiffe://c.example/u5", listCarol},
		{ptr(e.issuers[1]), "spiffe://b.example/p6", listBob},
		{nil, "", listCarol},
		{ptr(e.issuers[0]), "", listCarol},
		{nil, "spiffe://c.example/u9", listBob},
	} {
		kind := "svid"
		if d.spiffe == "" {
			kind = "generic"
		}
		r := store.CertificateRequest{ID: store.NewID(), TenantID: tenant, IssuerID: d.issuer, Kind: kind, SpiffeID: d.spiffe, SANs: []byte(fmt.Sprintf(`["d%d.example"]`, i)),
			RequestedBy: d.by, RequesterKind: "user", Status: "pending"}
		if err := e.db.InsertRequest(ctx, r); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		e.requests = append(e.requests, r.ID)
		j := store.CertificateJob{ID: store.NewID(), TenantID: tenant, RequestID: r.ID, Type: "issue", Status: "queued", MaxAttempts: 5, RunAfter: base}
		if err := e.db.InsertJob(ctx, j); err != nil {
			t.Fatalf("job: %v", err)
		}
		e.jobs = append(e.jobs, j.ID)
	}
	orphan := store.CertificateJob{ID: store.NewID(), TenantID: tenant, RequestID: store.NewID(), Type: "issue", Status: "failed", MaxAttempts: 5, RunAfter: base}
	if err := e.db.InsertJob(ctx, orphan); err != nil {
		t.Fatalf("orphan job: %v", err)
	}
	e.jobs = append(e.jobs, orphan.ID)
	grant := func(rt, id string) {
		if _, err := e.db.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tenant, ResourceType: rt, ResourceID: id, SubjectType: "user", SubjectID: listBob, Relation: "viewer"}); err != nil {
			t.Fatal(err)
		}
	}
	grant(authz.Issuer, e.issuers[0])
	grant(authz.Issuer, e.issuers[2])
	for i := 0; i < len(e.certs); i += 3 {
		grant(authz.Certificate, e.certs[i])
	}
	// An expired grant gives nothing.
	past := time.Now().Add(-time.Hour)
	if _, err := e.db.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: tenant, ResourceType: authz.Certificate, ResourceID: e.certs[1], SubjectType: "user", SubjectID: listBob, Relation: "owner", ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
}

// walk pages a whole list through fn, asserting a constant total and no
// repeated record.
func walk(t *testing.T, name string, size int, sort string, fn func(listquery.Request) ([]string, int, error)) []string {
	t.Helper()
	var all []string
	total := -1
	for p := 1; ; p++ {
		ids, n, err := fn(listquery.Request{Page: p, PageSize: size, Sort: sort})
		if err != nil {
			t.Fatalf("%s page %d: %v", name, p, err)
		}
		if total >= 0 && n != total {
			t.Fatalf("%s: total changed %d -> %d", name, total, n)
		}
		total = n
		for _, id := range ids {
			if slices.Contains(all, id) {
				t.Fatalf("%s: %s repeated on page %d", name, id, p)
			}
		}
		all = append(all, ids...)
		if len(all) >= total || len(ids) == 0 {
			break
		}
	}
	if len(all) != total {
		t.Fatalf("%s: walked %d of %d", name, len(all), total)
	}
	return all
}

func idsOf[T any](items []T, id func(T) string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, id(it))
	}
	return out
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// hidden reports whether a per-record read refused (forbidden or masked).
func hidden(err error) bool {
	return errors.Is(err, authz.ErrForbidden) || errors.Is(err, authz.ErrNotFound) || errors.Is(err, store.ErrNotFound)
}

func TestLists_TotalsAndPagesMatchPerRecordChecks(t *testing.T) {
	ctx := context.Background()
	e := newListEnv(t)
	type list struct {
		name  string
		all   []string
		admin int
		page  func(authz.Subjects, listquery.Request) ([]string, int, error)
		get   func(authz.Subjects, string) error
	}
	lists := []list{
		{"certificates", e.certs, 30,
			func(s authz.Subjects, r listquery.Request) ([]string, int, error) {
				p, err := e.iss.PageCertificates(ctx, s, issue.CertificateListFilter{}, r)
				return idsOf(p.Items, func(v issue.CertificateView) string { return v.ID }), p.Total, err
			},
			func(s authz.Subjects, id string) error { _, err := e.iss.GetCertificate(ctx, s, id); return err }},
		{"issuers", e.issuers, 3,
			func(s authz.Subjects, r listquery.Request) ([]string, int, error) {
				p, err := e.iss.PageIssuers(ctx, s, r)
				return idsOf(p.Items, func(v issue.IssuerView) string { return v.ID }), p.Total, err
			},
			func(s authz.Subjects, id string) error { _, err := e.iss.GetIssuer(ctx, s, id); return err }},
		{"requests", e.requests, 7,
			func(s authz.Subjects, r listquery.Request) ([]string, int, error) {
				p, err := e.enr.PageRequests(ctx, s, "", r)
				return idsOf(p.Items, func(v enroll.RequestView) string { return v.ID }), p.Total, err
			},
			func(s authz.Subjects, id string) error { _, err := e.enr.GetRequest(ctx, s, id); return err }},
		{"jobs", e.jobs, 11,
			func(s authz.Subjects, r listquery.Request) ([]string, int, error) {
				p, err := e.enr.PageJobs(ctx, s, "", r)
				return idsOf(p.Items, func(v enroll.JobView) string { return v.ID }), p.Total, err
			},
			func(s authz.Subjects, id string) error { _, err := e.enr.GetJob(ctx, s, id); return err }},
	}
	for _, l := range lists {
		readableBy := func(s authz.Subjects) []string {
			var out []string
			for _, id := range l.all {
				err := l.get(s, id)
				if err == nil {
					out = append(out, id)
				} else if !hidden(err) {
					t.Fatalf("%s get %s: %v", l.name, id, err)
				}
			}
			return sorted(out)
		}
		adminIDs := walk(t, l.name+"/admin", 200, "", func(r listquery.Request) ([]string, int, error) { return l.page(admin(), r) })
		if len(adminIDs) != l.admin || !slices.Equal(sorted(adminIDs), readableBy(admin())) {
			t.Fatalf("%s: admin list %d != admin per-record view", l.name, len(adminIDs))
		}
		want := readableBy(bob())
		if len(want) == 0 || len(want) == len(adminIDs) {
			t.Fatalf("%s: fixture must hide some records from bob (%d of %d)", l.name, len(want), len(adminIDs))
		}
		for _, size := range []int{1, 4, 7, 200} {
			got := walk(t, l.name+"/bob", size, "", func(r listquery.Request) ([]string, int, error) { return l.page(bob(), r) })
			if !slices.Equal(sorted(got), want) {
				t.Fatalf("%s size %d: bob sees %d, per-record view %d", l.name, size, len(got), len(want))
			}
		}
		// A subject without any grant sees (and counts) nothing.
		nobody := authz.Subjects{TenantID: tenant, UserID: "55555555-5555-7555-8555-555555555555"}
		if ids, total, err := l.page(nobody, listquery.Request{}); err != nil || total != 0 || len(ids) != 0 {
			t.Fatalf("%s: grantless subject sees %d (total %d, %v)", l.name, len(ids), total, err)
		}
	}
}

func TestLists_SortingAndClamp(t *testing.T) {
	ctx := context.Background()
	e := newListEnv(t)
	page := func(s authz.Subjects, sort string, order listquery.Dir) []string {
		return walk(t, "certificates/"+sort, 7, sort, func(r listquery.Request) ([]string, int, error) {
			r.Order = order
			p, err := e.iss.PageCertificates(ctx, s, issue.CertificateListFilter{}, r)
			return idsOf(p.Items, func(v issue.CertificateView) string { return v.ID }), p.Total, err
		})
	}
	for _, f := range []string{"identity", "issuer", "kind", "status", "not_before", "not_after", "created_at"} {
		asc, desc := page(admin(), f, listquery.Asc), page(admin(), f, listquery.Desc)
		if len(asc) != 30 || len(desc) != 30 {
			t.Fatalf("%s: %d/%d rows", f, len(asc), len(desc))
		}
		if f == "identity" || f == "not_after" || f == "created_at" {
			slices.Reverse(desc)
			if !slices.Equal(asc, desc) {
				t.Fatalf("%s: desc is not asc reversed", f)
			}
		}
	}
	if got := page(admin(), "identity", listquery.Asc); got[0] != e.certs[29] {
		t.Fatal("identity asc does not start at svc-00")
	}
	if got := page(admin(), "", ""); got[0] != maxID(e.certs[28], e.certs[29]) || got[29] != minID(e.certs[0], e.certs[1]) {
		t.Fatal("default order is not newest first with the id tie-break")
	}
	// List pages never carry sealed key bytes, only their presence.
	if err := e.db.St.Tx(ctx, store.Scope{TenantID: tenant}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE issued_certificates SET key_sealed = '\\xdeadbeef'::bytea WHERE id = $1", e.certs[0])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rows, _, _, err := e.db.PageCertificates(ctx, tenant, store.CertificatePageFilter{Visible: store.Visible{IDs: []string{e.certs[0], e.certs[3]}}}, listquery.Request{})
	if err != nil || len(rows) != 2 {
		t.Fatalf("visible page: %d (%v)", len(rows), err)
	}
	for _, r := range rows {
		if want := r.ID == e.certs[0]; (len(r.KeySealed) > 0) != want || len(r.KeySealed) > 1 {
			t.Fatalf("key marker of %s: %x", r.ID, r.KeySealed)
		}
	}
	ir, _, _, err := e.db.PageIssuers(ctx, tenant, store.Visible{All: true}, listquery.Request{})
	if err != nil || len(ir) != 3 {
		t.Fatal(err)
	}
	// An unpinned request with a malformed SPIFFE ID never resolves to a default issuer.
	bad := store.CertificateRequest{ID: store.NewID(), TenantID: tenant, Kind: "svid", SpiffeID: "spiffe://a.example/", SANs: []byte(`[]`), RequestedBy: listCarol, RequesterKind: "user", Status: "pending"}
	if err := e.db.InsertRequest(ctx, bad); err != nil {
		t.Fatal(err)
	}
	rp, err := e.enr.PageRequests(ctx, bob(), "", listquery.Request{PageSize: 200})
	if err != nil || slices.Contains(idsOf(rp.Items, func(v enroll.RequestView) string { return v.ID }), bad.ID) {
		t.Fatalf("malformed unpinned request visible (%v)", err)
	}
	// Beyond the last page: the last page, echoed.
	p, err := e.iss.PageCertificates(ctx, bob(), issue.CertificateListFilter{}, listquery.Request{Page: 99, PageSize: 3, Sort: "not_after"})
	if err != nil || p.Page != 4 || p.Total != 10 || len(p.Items) != 1 || p.Order != listquery.Asc {
		t.Fatalf("clamp: page %d total %d items %d order %s (%v)", p.Page, p.Total, len(p.Items), p.Order, err)
	}
	// Filters apply to the count as well.
	p, err = e.iss.PageCertificates(ctx, bob(), issue.CertificateListFilter{IssuerID: e.issuers[0]}, listquery.Request{})
	if err != nil || p.Total != 10 {
		t.Fatalf("issuer filter: total %d (%v)", p.Total, err)
	}
	p, err = e.iss.PageCertificates(ctx, bob(), issue.CertificateListFilter{IssuerID: e.issuers[1]}, listquery.Request{})
	if err != nil || p.Total != 0 {
		t.Fatalf("bob on issuer B: total %d (%v)", p.Total, err)
	}
	// Issuers sort by name case-insensitively.
	ip, err := e.iss.PageIssuers(ctx, admin(), listquery.Request{Sort: "name", Order: listquery.Desc})
	if err != nil || !slices.Equal(idsOf(ip.Items, func(v issue.IssuerView) string { return v.ID }), []string{e.issuers[2], e.issuers[1], e.issuers[0]}) {
		t.Fatalf("issuer names desc (%v)", err)
	}
	// Every sort field of every list is valid SQL.
	for _, f := range []string{"identity", "kind", "status", "created_at"} {
		if _, err := e.enr.PageRequests(ctx, bob(), "", listquery.Request{Sort: f}); err != nil {
			t.Fatalf("requests sort %s: %v", f, err)
		}
	}
	for _, f := range []string{"type", "status", "attempts", "run_after", "created_at"} {
		if _, err := e.enr.PageJobs(ctx, bob(), "queued", listquery.Request{Sort: f}); err != nil {
			t.Fatalf("jobs sort %s: %v", f, err)
		}
	}
}

func maxID(a, b string) string { return max(a, b) }
func minID(a, b string) string { return min(a, b) }

// The legacy certificate cursor (the last row's id) continues after that row:
// a full walk sees every readable certificate once.
func TestLists_LegacyCertificateCursorDoesNotRepeat(t *testing.T) {
	ctx := context.Background()
	e := newListEnv(t)
	for _, s := range []authz.Subjects{admin(), bob()} {
		seen := map[string]bool{}
		cursor := ""
		for range 20 {
			items, next, err := e.iss.ListCertificates(ctx, s, store.CertificateFilter{CursorID: cursor, Limit: 4})
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range items {
				if seen[c.ID] {
					t.Fatalf("cursor %s repeated %s", cursor, c.ID)
				}
				seen[c.ID] = true
			}
			if next == "" {
				break
			}
			cursor = next
		}
		want := 30
		if !s.IsAdmin() {
			want = 10
		}
		if len(seen) != want {
			t.Fatalf("legacy walk saw %d, want %d", len(seen), want)
		}
	}
}

// The cursor reads behind SVIDServer.Verify (by SPIFFE id, limit 50), the
// renewal scan and the backup walk are untouched by the page queries.
func TestLists_VerifyReadUnchanged(t *testing.T) {
	ctx := context.Background()
	e := newListEnv(t)
	got, err := e.db.ListCertificates(ctx, tenant, store.CertificateFilter{SpiffeID: "spiffe://a.example/svc-07", Limit: 50})
	if err != nil || len(got) != 1 || got[0].ID != e.certs[22] || got[0].CertPEM != "pem" {
		t.Fatalf("verify read: %d rows (%v)", len(got), err)
	}
	all, err := e.db.ListCertificates(ctx, tenant, store.CertificateFilter{Limit: 50})
	if err != nil || len(all) != 30 {
		t.Fatalf("cursor list: %d (%v)", len(all), err)
	}
	if other, err := e.db.ListCertificates(ctx, listOther, store.CertificateFilter{Limit: 50}); err != nil || len(other) != 0 {
		t.Fatalf("other tenant: %d (%v)", len(other), err)
	}
}

func TestLists_SecretsWebhooksAndAuditWindow(t *testing.T) {
	ctx := context.Background()
	e := newListEnv(t)
	for _, n := range []string{"zeta", "Alpha", "mid"} {
		if _, err := e.sec.Create(ctx, admin(), secrets.Input{Name: n, Kind: secrets.KindDNSCredential, Value: sealed.Settings{"token": "v-" + n}}); err != nil {
			t.Fatalf("secret: %v", err)
		}
		if err := e.db.InsertWebhook(ctx, store.WebhookEndpoint{ID: store.NewID(), TenantID: tenant, Name: n, URL: "https://hooks.example/" + n, Enabled: true, SecretSealed: []byte("x")}); err != nil {
			t.Fatalf("webhook: %v", err)
		}
	}
	sp, err := e.sec.Page(ctx, admin(), listquery.Request{PageSize: 2})
	if err != nil || sp.Total != 3 || len(sp.Items) != 2 || sp.Items[0].Name != "Alpha" || sp.Items[1].Name != "mid" {
		t.Fatalf("secrets page: %+v (%v)", sp, err)
	}
	rows, _, _, err := e.db.PageSecrets(ctx, tenant, listquery.Request{})
	if err != nil || len(rows) != 3 {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ValueSealed != nil {
			t.Fatal("a secrets page read the sealed value")
		}
	}
	wp, err := e.hooks.Page(ctx, admin(), listquery.Request{Sort: "name", Order: listquery.Desc})
	if err != nil || wp.Total != 3 || wp.Items[0].Name != "zeta" {
		t.Fatalf("webhooks page: %+v (%v)", wp, err)
	}
	if sp, err = e.sec.Page(ctx, authz.Subjects{TenantID: listOther, UserID: listBob}, listquery.Request{}); err != nil || sp.Total != 0 {
		t.Fatalf("other tenant secrets: %d (%v)", sp.Total, err)
	}

	now := time.Now().UTC()
	var ev []store.AuditRow
	for i, age := range []time.Duration{time.Hour, 2 * time.Hour, 2 * time.Hour, 6 * 24 * time.Hour, 8 * 24 * time.Hour, 30 * 24 * time.Hour} {
		ev = append(ev, store.AuditRow{TS: now.Add(-age), TenantID: tenant, EventType: "issuer_created", ActorKind: "user", ActorID: listCarol, SubjectKind: "issuer", SubjectID: fmt.Sprint(i), Outcome: "ok"})
	}
	ev = append(ev, store.AuditRow{TS: now, TenantID: listOther, EventType: "issuer_created", ActorKind: "user", Outcome: "ok"})
	if err := e.db.InsertAuditRows(ctx, ev); err != nil {
		t.Fatal(err)
	}
	window := store.AuditPageFilter{From: now.Add(-store.AuditWindow), To: now.Add(time.Second), ActorID: listCarol}
	var got []string
	walk(t, "audit", 1, "", func(r listquery.Request) ([]string, int, error) {
		rows, total, _, err := e.db.PageAudit(ctx, tenant, window, r)
		for _, x := range rows {
			got = append(got, x.SubjectID)
		}
		return idsOf(rows, func(x store.AuditRow) string { return fmt.Sprint(x.ID) }), total, err
	})
	// Newest first; the two events sharing a timestamp keep insertion order reversed.
	if !slices.Equal(got, []string{"0", "2", "1", "3"}) {
		t.Fatalf("audit window order %v", got)
	}
	_, total, _, err := e.db.PageAudit(ctx, tenant, store.AuditPageFilter{From: now.Add(-60 * 24 * time.Hour), To: now.Add(time.Second), ActorID: listCarol}, listquery.Request{})
	if err != nil || total != 6 {
		t.Fatalf("wide window: %d (%v)", total, err)
	}
	// The legacy cursor read still works (newest first).
	legacy, err := e.db.QueryAudit(ctx, tenant, store.AuditFilter{ActorID: listCarol, Limit: 2})
	if err != nil || len(legacy) != 2 || legacy[0].SubjectID != "0" {
		t.Fatalf("legacy audit: %v (%v)", legacy, err)
	}
}
