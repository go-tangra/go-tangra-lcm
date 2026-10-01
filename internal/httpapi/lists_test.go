package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// List contract (go-tangra specs/032-server-side-tables): pages, totals that
// count only what the caller may read, 422 on invalid parameters, the legacy
// cursor path for one release and the audit default window.

const apiCarol = "44444444-4444-7444-8444-444444444444"

const (
	tdA = "a.example" // has a default issuer bob may read
	tdB = "b.example" // has a default issuer bob may not read
)

type listSeed struct {
	issuers  []string // A (default tdA), B (default tdB), C (not default, tdA)
	certs    []string
	requests []string
	jobs     []string
}

// seedLists writes a tenant with three issuers, 12 certificates, 10 requests
// and 10 jobs straight into the memstore, plus bob's grants: read on issuer A
// and C (not B), read on every third certificate; a foreign tenant's rows
// must never show up.
func seedLists(t *testing.T, f *apiFixture) listSeed {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	var s listSeed
	for i, def := range []struct {
		name, td  string
		isDefault bool
	}{{"Alpha", tdA, true}, {"Bravo", tdB, true}, {"charlie", tdA, false}} {
		id := fmt.Sprintf("00000000-0000-7000-8000-0000000000a%d", i)
		f.mem.Issuers[id] = store.Issuer{ID: id, TenantID: apiTenant, Name: def.name, Type: "self_signed", TrustDomain: def.td, IsDefault: def.isDefault, Enabled: true,
			CreatedAt: base.Add(time.Duration(i) * time.Hour)}
		s.issuers = append(s.issuers, id)
	}
	foreignIssuer := "00000000-0000-7000-8000-0000000000af"
	f.mem.Issuers[foreignIssuer] = store.Issuer{ID: foreignIssuer, TenantID: "99999999-9999-7999-8999-999999999999", Name: "Foreign", Type: "self_signed", TrustDomain: tdA, IsDefault: true}
	for i := range 12 {
		id := fmt.Sprintf("00000000-0000-7000-8000-0000000001%02d", i)
		// Pairs share a creation time: the id tie-breaker keeps pages stable.
		created := base.Add(time.Duration(i/2) * time.Minute)
		f.mem.Certificates[id] = store.IssuedCertificate{ID: id, TenantID: apiTenant, IssuerID: s.issuers[i%3], Kind: "svid", Serial: fmt.Sprint(i),
			SpiffeID: fmt.Sprintf("spiffe://%s/svc-%02d", tdA, 11-i), Status: "active", NotBefore: created, NotAfter: created.Add(time.Duration(48-i) * time.Hour),
			CreatedAt: created, UpdatedAt: created}
		s.certs = append(s.certs, id)
	}
	f.mem.Certificates["00000000-0000-7000-8000-0000000001ff"] = store.IssuedCertificate{ID: "00000000-0000-7000-8000-0000000001ff", TenantID: "99999999-9999-7999-8999-999999999999", IssuerID: foreignIssuer, Status: "active", CreatedAt: base}
	ptr := func(v string) *string { return &v }
	reqDefs := []struct {
		issuer *string
		spiffe string
		by     string
	}{
		{ptr(s.issuers[0]), "spiffe://" + tdA + "/p0", apiCarol}, // pinned A: bob reads
		{ptr(s.issuers[1]), "spiffe://" + tdB + "/p1", apiCarol}, // pinned B: hidden
		{ptr(s.issuers[2]), "spiffe://" + tdA + "/p2", apiCarol}, // pinned C: bob reads
		{nil, "spiffe://" + tdA + "/u3", apiCarol},               // default A: bob reads
		{nil, "spiffe://" + tdB + "/u4", apiCarol},               // default B: hidden
		{nil, "spiffe://c.example/u5", apiCarol},                 // no default issuer: hidden (also for admins)
		{ptr(s.issuers[1]), "spiffe://" + tdB + "/p6", apiBob},   // bob's own: bob reads
		{nil, "", apiCarol},                    // generic without issuer: hidden
		{ptr(s.issuers[0]), "", apiCarol},      // generic pinned A: bob reads
		{nil, "spiffe://c.example/u9", apiBob}, // bob's own, no issuer: bob reads
	}
	for i, d := range reqDefs {
		id := fmt.Sprintf("00000000-0000-7000-8000-0000000002%02d", i)
		kind := "svid"
		if d.spiffe == "" {
			kind = "generic"
		}
		f.mem.Requests[id] = store.CertificateRequest{ID: id, TenantID: apiTenant, IssuerID: d.issuer, Kind: kind, SpiffeID: d.spiffe, SANs: []byte(fmt.Sprintf(`["d%d.example"]`, i)),
			RequestedBy: d.by, RequesterKind: "user", Status: []string{"pending", "issued"}[i%2], CreatedAt: base.Add(time.Duration(i) * time.Second)}
		s.requests = append(s.requests, id)
		jid := fmt.Sprintf("00000000-0000-7000-8000-0000000003%02d", i)
		f.mem.Jobs[jid] = store.CertificateJob{ID: jid, TenantID: apiTenant, RequestID: id, Type: "issue", Status: "queued", RunAfter: base, CreatedAt: base.Add(time.Duration(i) * time.Second)}
		s.jobs = append(s.jobs, jid)
	}
	// An orphan job (its request is gone): administrators only.
	orphan := "00000000-0000-7000-8000-0000000003ff"
	f.mem.Jobs[orphan] = store.CertificateJob{ID: orphan, TenantID: apiTenant, RequestID: "00000000-0000-7000-8000-0000000002ff", Type: "issue", Status: "failed", CreatedAt: base}
	s.jobs = append(s.jobs, orphan)

	grant := func(rt, id string) {
		if _, err := f.mem.UpsertGrant(ctx, store.Grant{ID: store.NewID(), TenantID: apiTenant, ResourceType: rt, ResourceID: id, SubjectType: "user", SubjectID: apiBob, Relation: "viewer"}); err != nil {
			t.Fatal(err)
		}
	}
	grant("issuer", s.issuers[0])
	grant("issuer", s.issuers[2])
	for i := 0; i < len(s.certs); i += 3 {
		grant("certificate", s.certs[i])
	}
	return s
}

// page fetches one list page as tok and returns the ids and the body.
func (f *apiFixture) page(t *testing.T, path, tok string, q url.Values) ([]string, map[string]any) {
	t.Helper()
	w := f.req(t, "GET", Prefix+path+"?"+q.Encode(), tok, "")
	mustStatus(t, w, http.StatusOK)
	body := jsonBody(t, w)
	items, _ := body["items"].([]any)
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.(map[string]any)["id"].(string))
	}
	return ids, body
}

// walk pages through a whole list with the given size and sort, asserting
// every page reports the same total and no record repeats.
func (f *apiFixture) walk(t *testing.T, path, tok string, size int, sort, order string) ([]string, int) {
	t.Helper()
	var all []string
	total := -1
	for p := 1; ; p++ {
		q := url.Values{"page": {fmt.Sprint(p)}, "page_size": {fmt.Sprint(size)}}
		if sort != "" {
			q.Set("sort", sort)
			q.Set("order", order)
		}
		ids, body := f.page(t, path, tok, q)
		n := int(body["total"].(float64))
		if total >= 0 && n != total {
			t.Fatalf("%s: total changed %d -> %d", path, total, n)
		}
		total = n
		for _, id := range ids {
			if slices.Contains(all, id) {
				t.Fatalf("%s: %s repeated on page %d", path, id, p)
			}
		}
		all = append(all, ids...)
		if len(all) >= total || len(ids) == 0 {
			break
		}
	}
	if len(all) != total {
		t.Fatalf("%s: walked %d of %d", path, len(all), total)
	}
	return all, total
}

// readable filters ids to those tok may GET one by one (the per-record check).
func (f *apiFixture) readable(t *testing.T, path, tok string, ids []string) []string {
	t.Helper()
	var out []string
	for _, id := range ids {
		w := f.req(t, "GET", Prefix+path+"/"+id, tok, "")
		switch w.Code {
		case http.StatusOK:
			out = append(out, id)
		case http.StatusNotFound, http.StatusForbidden:
		default:
			t.Fatalf("GET %s/%s: %d", path, id, w.Code)
		}
	}
	return out
}

func reversed(s []string) []string {
	out := slices.Clone(s)
	slices.Reverse(out)
	return out
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// A user with partial grants sees exactly the admin view filtered by the
// per-record read check, with exact totals, on every per-record-authorized
// list; foreign tenants never appear.
func TestListsTotalsMatchPerRecordChecks(t *testing.T) {
	f := newAPI(t)
	s := seedLists(t, f)
	for _, c := range []struct {
		path      string
		all       []string
		adminSeen int // what the admin view holds (requests: those with a resolvable issuer, or their own)
	}{
		{"/certificates", s.certs, 12},
		{"/issuers", s.issuers, 3},
		{"/requests", s.requests, 7},
		{"/jobs", s.jobs, 11},
	} {
		adminIDs, adminTotal := f.walk(t, c.path, "admin", 200, "", "")
		if adminTotal != c.adminSeen {
			t.Fatalf("%s: admin total %d, want %d", c.path, adminTotal, c.adminSeen)
		}
		// The admin view agrees with the admin's own per-record checks.
		if got, want := sortedCopy(adminIDs), sortedCopy(f.readable(t, c.path, "admin", c.all)); !slices.Equal(got, want) {
			t.Fatalf("%s: admin list %v != admin readable %v", c.path, got, want)
		}
		// bob's view: every record bob may read one by one (requests: the
		// requester also reads their own, even one an admin cannot resolve).
		want := sortedCopy(f.readable(t, c.path, "bob", c.all))
		for _, size := range []int{1, 2, 3, 200} {
			got, total := f.walk(t, c.path, "bob", size, "", "")
			if total != len(want) || !slices.Equal(sortedCopy(got), want) {
				t.Fatalf("%s size %d: bob sees %v (total %d), want %v", c.path, size, got, total, want)
			}
		}
		if len(want) == 0 || len(want) == adminTotal {
			t.Fatalf("%s: fixture must hide some but not all records (bob %d of %d)", c.path, len(want), adminTotal)
		}
	}
}

// Sorting orders the whole list on the server with a stable id tie-break,
// in both directions.
func TestListsSortWholeList(t *testing.T) {
	f := newAPI(t)
	s := seedLists(t, f)
	asc, _ := f.walk(t, "/certificates", "admin", 5, "identity", "asc")
	desc, _ := f.walk(t, "/certificates", "admin", 5, "identity", "desc")
	if !slices.Equal(asc, reversed(desc)) {
		t.Fatalf("identity asc %v is not desc %v reversed", asc, desc)
	}
	if asc[0] != s.certs[11] { // svc-00
		t.Fatalf("identity asc starts with %s", asc[0])
	}
	// Default order: newest first; equal creation times break on the id.
	def, _ := f.walk(t, "/certificates", "admin", 4, "", "")
	if def[0] != s.certs[11] || def[1] != s.certs[10] || def[11] != s.certs[0] {
		t.Fatalf("default order %v", def)
	}
	notAfter, _ := f.walk(t, "/certificates", "bob", 1, "not_after", "asc")
	if len(notAfter) != 4 || notAfter[0] != s.certs[9] {
		t.Fatalf("bob not_after asc %v", notAfter)
	}
	issuers, _ := f.walk(t, "/issuers", "admin", 200, "name", "desc")
	if !slices.Equal(issuers, []string{s.issuers[2], s.issuers[1], s.issuers[0]}) {
		t.Fatalf("issuer names desc %v", issuers)
	}
}

// A page beyond the end answers the last page; the response echoes the
// applied request.
func TestListsClampAndEcho(t *testing.T) {
	f := newAPI(t)
	seedLists(t, f)
	ids, body := f.page(t, "/certificates", "bob", url.Values{"page": {"99"}, "page_size": {"3"}, "sort": {"not_after"}})
	if len(ids) != 1 || body["page"].(float64) != 2 || body["total"].(float64) != 4 || body["page_size"].(float64) != 3 ||
		body["sort"] != "not_after" || body["order"] != "asc" {
		t.Fatalf("clamped page: %v", body)
	}
	ids, body = f.page(t, "/secrets", "admin", nil)
	if len(ids) != 0 || body["total"].(float64) != 0 || body["page"].(float64) != 1 || body["sort"] != "name" {
		t.Fatalf("empty secrets page: %v", body)
	}
}

func TestListsRejectInvalidParameters(t *testing.T) {
	f := newAPI(t)
	for _, path := range []string{"/certificates", "/issuers", "/requests", "/jobs", "/secrets", "/webhooks", "/audit"} {
		for _, c := range []struct{ q, param string }{
			{"sort=value_sealed", "sort"},
			{"sort=key_sealed", "sort"},
			{"sort=id%3B+DROP+TABLE+issuers", "sort"},
			{"order=sideways", "order"},
			{"page=0", "page"},
			{"page=abc", "page"},
			{"page_size=0", "page_size"},
			{"page_size=201", "page_size"},
		} {
			w := f.req(t, "GET", Prefix+path+"?"+c.q, "admin", "")
			mustStatus(t, w, http.StatusUnprocessableEntity)
			body := jsonBody(t, w)
			detail, _ := body["detail"].(map[string]any)
			if body["reason"] != "validation_failed" || detail["param"] != c.param {
				t.Fatalf("%s?%s: %v", path, c.q, body)
			}
		}
	}
	// Mixing the legacy and the page style names the cursor.
	for _, path := range []string{"/certificates", "/issuers", "/requests", "/jobs", "/audit"} {
		w := f.req(t, "GET", Prefix+path+"?cursor=x&page=2", "admin", "")
		mustStatus(t, w, http.StatusUnprocessableEntity)
		if d, _ := jsonBody(t, w)["detail"].(map[string]any); d["param"] != "cursor" {
			t.Fatalf("%s mixed styles: %v", path, d)
		}
	}
	// A list's sort enum is its own: a field of another list is refused.
	mustStatus(t, f.req(t, "GET", Prefix+"/issuers?sort=not_after", "admin", ""), http.StatusUnprocessableEntity)
	// The handler enforces the same rules without the document's validation.
	_ = listParamErrorParam(t)
	// The service rules apply to internal callers that bypass the document.
	if _, err := listquery.Parse(url.Values{"sort": {"value_sealed"}}, store.SecretList); err == nil {
		t.Fatal("secret value sortable")
	}
}

// listParamErrorParam covers the fallback of a non-listquery error.
func listParamErrorParam(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	listParamError(w, fmt.Errorf("other"))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("fallback status %d", w.Code)
	}
	return w.Body.String()
}

// The legacy cursor/limit style keeps its shape plus the total; the
// certificate cursor continues after the last row instead of repeating page 1.
func TestListsLegacyPath(t *testing.T) {
	f := newAPI(t)
	s := seedLists(t, f)
	seen := map[string]bool{}
	cursor := ""
	for range 10 {
		w := f.req(t, "GET", Prefix+"/certificates?limit=5&cursor="+cursor, "admin", "")
		mustStatus(t, w, http.StatusOK)
		body := jsonBody(t, w)
		if _, ok := body["page"]; ok {
			t.Fatal("legacy response carries page fields")
		}
		if body["total"].(float64) != 12 {
			t.Fatalf("legacy total %v", body["total"])
		}
		items := body["items"].([]any)
		for _, it := range items {
			id := it.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("legacy cursor repeated %s", id)
			}
			seen[id] = true
		}
		cursor, _ = body["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(seen) != len(s.certs) {
		t.Fatalf("legacy walk saw %d of %d", len(seen), len(s.certs))
	}
	// bob's legacy listing counts only what bob may read.
	w := f.req(t, "GET", Prefix+"/certificates?limit=2", "bob", "")
	mustStatus(t, w, http.StatusOK)
	if b := jsonBody(t, w); b["total"].(float64) != 4 || len(b["items"].([]any)) != 2 || b["next_cursor"] == "" {
		t.Fatalf("bob legacy page %v", b)
	}
	// A cursor naming a certificate bob may not read behaves as unknown (its
	// position must not reveal that it exists).
	w = f.req(t, "GET", Prefix+"/certificates?limit=2&cursor="+s.certs[1], "bob", "")
	mustStatus(t, w, http.StatusOK)
	if items := jsonBody(t, w)["items"].([]any); len(items) != 0 {
		t.Fatalf("unreadable cursor: %d items", len(items))
	}
	// An unknown or malformed cursor ends the list.
	for _, c := range []string{"00000000-0000-7000-8000-00000000ffff", "not-a-uuid"} {
		w = f.req(t, "GET", Prefix+"/certificates?limit=2&cursor="+c, "admin", "")
		mustStatus(t, w, http.StatusOK)
		if items := jsonBody(t, w)["items"].([]any); len(items) != 0 {
			t.Fatalf("cursor %s: %d items", c, len(items))
		}
	}
	for _, path := range []string{"/issuers", "/requests", "/jobs"} {
		w := f.req(t, "GET", Prefix+path+"?limit=50", "bob", "")
		mustStatus(t, w, http.StatusOK)
		b := jsonBody(t, w)
		if _, ok := b["next_cursor"]; !ok || b["total"] == nil {
			t.Fatalf("%s legacy shape %v", path, b)
		}
		if int(b["total"].(float64)) != len(b["items"].([]any)) {
			t.Fatalf("%s legacy total %v != items %d", path, b["total"], len(b["items"].([]any)))
		}
	}
}

// Audit pages cover the last 7 days unless from/to say otherwise, with exact
// totals inside the window; from after to is refused.
func TestAuditDefaultWindow(t *testing.T) {
	f := newAPI(t)
	now := time.Now().UTC()
	var rows []store.AuditRow
	for i, age := range []time.Duration{time.Hour, 2 * time.Hour, 2 * time.Hour, 6 * 24 * time.Hour, 8 * 24 * time.Hour, 30 * 24 * time.Hour} {
		rows = append(rows, store.AuditRow{TS: now.Add(-age), TenantID: apiTenant, EventType: "issuer_created", ActorKind: "user", ActorID: apiAdmin,
			SubjectKind: "issuer", SubjectID: fmt.Sprint(i), Outcome: "ok"})
	}
	if err := f.mem.InsertAuditRows(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	ids, body := f.page(t, "/audit", "admin", nil)
	if body["total"].(float64) != 4 || len(ids) != 4 || body["sort"] != "ts" || body["order"] != "desc" {
		t.Fatalf("default window: %v", body)
	}
	// Equal timestamps keep a stable order (the id tie-breaker): newest first.
	if !slices.Equal(ids, []string{"1", "3", "2", "4"}) {
		t.Fatalf("default order %v", ids)
	}
	asc, _ := f.page(t, "/audit", "admin", url.Values{"order": {"asc"}})
	if !slices.Equal(asc, []string{"4", "2", "3", "1"}) {
		t.Fatalf("asc order %v", asc)
	}
	_, body = f.page(t, "/audit", "admin", url.Values{"from": {now.Add(-60 * 24 * time.Hour).Format(time.RFC3339)}})
	if body["total"].(float64) != 6 {
		t.Fatalf("explicit from: %v", body["total"])
	}
	_, body = f.page(t, "/audit", "admin", url.Values{"to": {now.Add(-7 * 24 * time.Hour).Format(time.RFC3339)}})
	if body["total"].(float64) != 1 { // the 8-day-old event: the window ends at to
		t.Fatalf("explicit to: %v", body["total"])
	}
	for _, q := range []url.Values{
		{"from": {now.Format(time.RFC3339)}, "to": {now.Add(-time.Hour).Format(time.RFC3339)}},
	} {
		w := f.req(t, "GET", Prefix+"/audit?"+q.Encode(), "admin", "")
		mustStatus(t, w, http.StatusUnprocessableEntity)
		if d, _ := jsonBody(t, w)["detail"].(map[string]any); d["param"] != "from" {
			t.Fatalf("from after to: %v", d)
		}
	}
	// The span is capped at store.MaxAuditSpan on the paged and legacy paths:
	// one day over is refused naming "from" (never echoing it), exactly 90
	// days is served (security review F-2).
	wideFrom, exactFrom := now.Add(-91*24*time.Hour).Format(time.RFC3339), now.Add(-90*24*time.Hour).Format(time.RFC3339)
	for _, q := range []url.Values{
		{"from": {wideFrom}, "to": {now.Format(time.RFC3339)}},
		{"from": {wideFrom}},
		{"from": {"1970-01-01T00:00:00Z"}, "page_size": {"10"}},
		{"from": {wideFrom}, "to": {now.Format(time.RFC3339)}, "limit": {"10"}},
		{"from": {"1970-01-01T00:00:00Z"}, "cursor": {now.Format(time.RFC3339Nano)}},
	} {
		w := f.req(t, "GET", Prefix+"/audit?"+q.Encode(), "admin", "")
		mustStatus(t, w, http.StatusUnprocessableEntity)
		b := jsonBody(t, w)
		if d, _ := b["detail"].(map[string]any); b["reason"] != "validation_failed" || d["param"] != "from" {
			t.Fatalf("%v: %v", q, b)
		}
		if strings.Contains(w.Body.String(), "1970") || strings.Contains(w.Body.String(), wideFrom) {
			t.Fatalf("%v echoed: %s", q, w.Body.String())
		}
	}
	if _, body = f.page(t, "/audit", "admin", url.Values{"from": {exactFrom}, "to": {now.Format(time.RFC3339)}}); body["total"].(float64) != 6 {
		t.Fatalf("90-day span: %v", body["total"])
	}
	w := f.req(t, "GET", Prefix+"/audit?"+url.Values{"from": {exactFrom}, "to": {now.Format(time.RFC3339)}, "limit": {"50"}}.Encode(), "admin", "")
	mustStatus(t, w, http.StatusOK)
	if n := len(jsonBody(t, w)["items"].([]any)); n != 6 {
		t.Fatalf("legacy 90-day span: %d", n)
	}
	// The legacy cursor path without from covers the default window too.
	w = f.req(t, "GET", Prefix+"/audit?limit=50", "admin", "")
	mustStatus(t, w, http.StatusOK)
	if n := len(jsonBody(t, w)["items"].([]any)); n != 4 {
		t.Fatalf("legacy default window: %d", n)
	}
	// Malformed window values name the parameter.
	for _, c := range []struct{ from, to, param string }{{"yesterday", "", "from"}, {"", "soon", "to"}, {"1970-01-01T00:00:00Z", "", "from"}} {
		if _, _, p := auditWindow(c.from, c.to, now); p != c.param {
			t.Fatalf("auditWindow(%q,%q) = %q", c.from, c.to, p)
		}
	}
	// Other tenants' events are never counted.
	if err := f.mem.InsertAuditRows(context.Background(), []store.AuditRow{{TS: now, TenantID: "99999999-9999-7999-8999-999999999999", EventType: "x", ActorKind: "user", Outcome: "ok"}}); err != nil {
		t.Fatal(err)
	}
	if _, body = f.page(t, "/audit", "admin", nil); body["total"].(float64) != 4 {
		t.Fatalf("foreign tenant counted: %v", body["total"])
	}
}

// Secrets and webhooks page by name; sealed material is never read.
func TestSecretAndWebhookPages(t *testing.T) {
	f := newAPI(t)
	for i, name := range []string{"zeta", "Alpha", "mid"} {
		id := fmt.Sprintf("00000000-0000-7000-8000-0000000004%02d", i)
		f.mem.Secrets[id] = store.TenantSecret{ID: id, TenantID: apiTenant, Name: name, Kind: "dns_credential", ValueSealed: []byte("sealed")}
		wid := fmt.Sprintf("00000000-0000-7000-8000-0000000005%02d", i)
		f.mem.Webhooks[wid] = store.WebhookEndpoint{ID: wid, TenantID: apiTenant, Name: name, URL: "https://hooks.example/" + name, SecretSealed: []byte("sealed")}
	}
	for _, path := range []string{"/secrets", "/webhooks"} {
		w := f.req(t, "GET", Prefix+path+"?page_size=2", "admin", "")
		mustStatus(t, w, http.StatusOK)
		body := jsonBody(t, w)
		items := body["items"].([]any)
		if body["total"].(float64) != 3 || len(items) != 2 || items[0].(map[string]any)["name"] != "Alpha" || items[1].(map[string]any)["name"] != "mid" {
			t.Fatalf("%s page: %v", path, body)
		}
	}
	rows, total, _, err := f.mem.PageSecrets(context.Background(), apiTenant, listquery.Request{})
	if err != nil || total != 3 || len(rows) != 3 {
		t.Fatalf("memstore secrets page: %d/%d %v", len(rows), total, err)
	}
	for _, r := range rows {
		if r.ValueSealed != nil {
			t.Fatal("a secrets page carries the sealed value")
		}
	}
}
