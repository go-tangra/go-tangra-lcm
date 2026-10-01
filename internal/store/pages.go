package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"
)

// List-contract pages (go-tangra specs/032-server-side-tables): count the rows
// matching the filter AND the caller's visibility, clamp the request to the
// last page, then select the page under the very same WHERE clause, ORDER BY
// the Spec's constant expressions with the id tie-breaker. Hidden records are
// therefore never counted nor returned (research D5). The cursor variants
// (ListX) stay for the gRPC RPCs, the renewal scan and the backup walks.
//
// Pages of tables with a uuid primary key are deferred joins (specs/032
// perf.md fix 3): the filter, ORDER BY, LIMIT and OFFSET run in a subquery
// that selects only the key (narrow tuples, often an index-only scan), and
// the full columns are read for the page's rows alone, in the subquery's
// order. A deep page then neither sorts nor skips wide rows (cert_pem) and
// never spills the sort to disk.

// pageQuery names the parts of one page query; cols, from, join, where and
// key are constants, where is parameterised by args.
type pageQuery struct {
	cols  string
	from  string // the listed table with its alias, e.g. "issued_certificates c"
	join  string // joins only the sort needs (page subquery only, never counted)
	where string
	key   string // the table's unique key (e.g. "c.id") for the deferred join; "" selects directly
}

// pageSQL is the page query of q under orderBy, limit and offset.
func pageSQL(q pageQuery, orderBy string, limit, offset int) string {
	if q.key == "" {
		return fmt.Sprintf("SELECT %s FROM %s%s WHERE %s ORDER BY %s LIMIT %d OFFSET %d",
			q.cols, q.from, q.join, q.where, orderBy, limit, offset)
	}
	// ARRAY(subquery) keeps the subquery's order; WITH ORDINALITY numbers it.
	return fmt.Sprintf("SELECT %s FROM unnest(ARRAY(SELECT %s FROM %s%s WHERE %s ORDER BY %s LIMIT %d OFFSET %d)) WITH ORDINALITY AS page_ids(pid, pos) "+
		"JOIN %s ON %s = page_ids.pid ORDER BY page_ids.pos",
		q.cols, q.key, q.from, q.join, q.where, orderBy, limit, offset, q.from, q.key)
}

// args collects positional parameters and returns their $n placeholder.
type args []any

func (a *args) add(v any) string {
	*a = append(*a, v)
	return fmt.Sprintf("$%d", len(*a))
}

// runPage counts, clamps and selects one page.
func runPage[T any](ctx context.Context, tx pgx.Tx, q pageQuery, a args, spec listquery.Spec, req listquery.Request,
	scan func(pgx.Rows) (T, error)) ([]T, int, listquery.Request, error) {
	req = ListRequest(req, spec)
	var total int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+q.from+" WHERE "+q.where, a...).Scan(&total); err != nil {
		return nil, 0, req, err
	}
	req = req.Clamp(total)
	rows, err := tx.Query(ctx, pageSQL(q, req.OrderBy(spec), req.Limit(), req.Offset()), a...)
	if err != nil {
		return nil, 0, req, err
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, serr := scan(rows)
		if serr != nil {
			return nil, 0, req, serr
		}
		out = append(out, v)
	}
	return out, total, req, rows.Err()
}

// visibleCond restricts col to v (" AND …"); the zero Visible matches nothing.
func visibleCond(v Visible, col string, a *args) string {
	if v.All {
		return ""
	}
	return " AND " + col + " = ANY(" + a.add(nonNil(v.IDs)) + "::uuid[])"
}

// uuidCond is " AND col = $n::uuid" for a non-empty value (col a uuid column,
// compared without a cast on the column so its index applies); a value that
// is no UUID matches nothing.
func uuidCond(col, v string, a *args) string {
	switch {
	case v == "":
		return ""
	case !IsUUID(v):
		return " AND false"
	}
	return " AND " + col + " = " + a.add(v) + "::uuid"
}

// eqCond is " AND col = $n" for a non-empty value.
func eqCond(col, v string, a *args) string {
	if v == "" {
		return ""
	}
	return " AND " + col + " = " + a.add(v)
}

// SpiffeShape is the SPIFFE ID shape an unpinned request must have to resolve
// to its trust domain's default issuer (lowercase trust domain, non-empty path).
const SpiffeShape = `^spiffe://[a-z0-9.-]+/[^?#]+$`

// requestIssuerReadable is the condition under which the caller may read the
// issuer request row r is (or would be) issued from (RequestScope).
func requestIssuerReadable(s RequestScope, a *args) string {
	pinned := "r.issuer_id IS NOT NULL"
	if !s.AllPinned {
		pinned = "r.issuer_id = ANY(" + a.add(nonNil(s.Issuers)) + "::uuid[])"
	}
	// An unpinned request resolves to the default issuer of its SPIFFE ID's
	// trust domain (spiffe://<trust-domain>/<path>: the third '/' field).
	// The shape guard keeps SQL from ever being wider than csr.ParseSPIFFEID
	// (no empty path, userinfo, port, query or fragment).
	byDefault := "(r.issuer_id IS NULL AND r.spiffe_id ~ '" + SpiffeShape + "' AND split_part(r.spiffe_id, '/', 3) = ANY(" + a.add(nonNil(s.DefaultDomains)) + "::text[]))"
	return "(" + pinned + " OR " + byDefault + ")"
}

// certPageCols / issuerPageCols are the list-page columns: a certificate's
// sealed key is replaced by a one-byte presence marker (the view only reports
// has_key) and an issuer's sealed settings are not read at all.
var (
	certPageCols   = strings.Replace(certCols, "key_sealed", "CASE WHEN key_sealed IS NULL THEN NULL ELSE '\\x01'::bytea END", 1)
	issuerPageCols = strings.Replace(issuerCols, "i.settings_sealed", "NULL::bytea", 1)
)

// PageCertificates pages the certificates matching f that f.Visible allows.
// Only a caller with tenant-wide read sorts "issuer" by name (through the
// issuer join); everyone else sorts it by issuer id (CertificateListFor).
func PageCertificates(ctx context.Context, tx pgx.Tx, tenantID string, f CertificatePageFilter, req listquery.Request) ([]IssuedCertificate, int, listquery.Request, error) {
	q, a, spec := certificatePage(tenantID, f, req)
	return runPage(ctx, tx, q, a, spec, req,
		func(r pgx.Rows) (IssuedCertificate, error) { return scanCertificate(r) })
}

func certificatePage(tenantID string, f CertificatePageFilter, req listquery.Request) (pageQuery, args, listquery.Spec) {
	var a args
	where := "c.tenant_id = " + a.add(tenantID) +
		uuidCond("c.issuer_id", f.IssuerID, &a) + eqCond("c.spiffe_id", f.SpiffeID, &a) + eqCond("c.status", f.Status, &a) +
		visibleCond(f.Visible, "c.id", &a)
	spec := CertificateListFor(f.Visible)
	q := pageQuery{cols: certPageCols, from: "issued_certificates c", where: where, key: "c.id"}
	if f.Visible.All && ListRequest(req, spec).Sort == "issuer" {
		q.join = CertificateIssuerJoin
	}
	return q, a, spec
}

// CertificatePageSQL is the page query PageCertificates runs for req (not
// clamped to the total) with its arguments, for EXPLAIN in tests and
// diagnostics.
func CertificatePageSQL(tenantID string, f CertificatePageFilter, req listquery.Request) (string, []any) {
	q, a, spec := certificatePage(tenantID, f, req)
	req = ListRequest(req, spec)
	return pageSQL(q, req.OrderBy(spec), req.Limit(), req.Offset()), a
}

// PageIssuers pages the issuers v allows.
func PageIssuers(ctx context.Context, tx pgx.Tx, tenantID string, v Visible, req listquery.Request) ([]Issuer, int, listquery.Request, error) {
	var a args
	where := "i.tenant_id = " + a.add(tenantID) + visibleCond(v, "i.id", &a)
	return runPage(ctx, tx, pageQuery{cols: issuerPageCols, from: "issuers i", where: where, key: "i.id"}, a, IssuerList, req,
		func(r pgx.Rows) (Issuer, error) { return scanIssuer(r) })
}

// PageRequests pages the certificate requests with status (all when empty)
// that s allows.
func PageRequests(ctx context.Context, tx pgx.Tx, tenantID, status string, s RequestScope, req listquery.Request) ([]CertificateRequest, int, listquery.Request, error) {
	var a args
	where := "r.tenant_id = " + a.add(tenantID) + eqCond("r.status", status, &a)
	readable := requestIssuerReadable(s, &a)
	if s.Actor != "" {
		readable = "(r.requested_by = " + a.add(s.Actor) + " OR " + readable + ")"
	}
	where += " AND " + readable
	return runPage(ctx, tx, pageQuery{cols: requestCols, from: "certificate_requests r", where: where, key: "r.id"}, a, RequestList, req,
		func(r pgx.Rows) (CertificateRequest, error) { return scanRequest(r) })
}

// PageJobs pages the certificate jobs with status (all when empty) that s
// allows (read through the job's request's issuer).
func PageJobs(ctx context.Context, tx pgx.Tx, tenantID, status string, s RequestScope, req listquery.Request) ([]CertificateJob, int, listquery.Request, error) {
	var a args
	where := "j.tenant_id = " + a.add(tenantID) + eqCond("j.status", status, &a)
	if !s.AllJobs {
		where += " AND EXISTS (SELECT 1 FROM certificate_requests r WHERE r.tenant_id = j.tenant_id AND r.id = j.request_id AND " +
			requestIssuerReadable(RequestScope{Issuers: s.Issuers, DefaultDomains: s.DefaultDomains}, &a) + ")"
	}
	return runPage(ctx, tx, pageQuery{cols: jobCols, from: "certificate_jobs j", where: where, key: "j.id"}, a, JobList, req,
		func(r pgx.Rows) (CertificateJob, error) { return scanJob(r) })
}

// secretPageCols are the secret columns of a list page: the sealed value is
// never read for a listing (nor sortable).
const secretPageCols = "id, tenant_id, name, kind, NULL::bytea, created_by, updated_by, created_at, updated_at" // #nosec G101 -- SQL column list, not a credential

// PageSecrets pages the tenant's secrets (metadata only).
func PageSecrets(ctx context.Context, tx pgx.Tx, tenantID string, req listquery.Request) ([]TenantSecret, int, listquery.Request, error) {
	var a args
	return runPage(ctx, tx, pageQuery{cols: secretPageCols, from: "tenant_secrets s", where: "s.tenant_id = " + a.add(tenantID), key: "s.id"}, a, SecretList, req,
		func(r pgx.Rows) (TenantSecret, error) { return scanSecret(r) })
}

// webhookPageCols are the webhook columns of a list page: the sealed signing
// secret is never read for a listing.
const webhookPageCols = "id, tenant_id, name, url, event_types, NULL::bytea, enabled, created_by, updated_by, created_at, updated_at"

// PageWebhooks pages the tenant's webhook endpoints.
func PageWebhooks(ctx context.Context, tx pgx.Tx, tenantID string, req listquery.Request) ([]WebhookEndpoint, int, listquery.Request, error) {
	var a args
	return runPage(ctx, tx, pageQuery{cols: webhookPageCols, from: "webhook_endpoints w", where: "w.tenant_id = " + a.add(tenantID), key: "w.id"}, a, WebhookList, req,
		func(r pgx.Rows) (WebhookEndpoint, error) { return scanWebhook(r) })
}

// PageAudit pages the tenant's audit events within [f.From, f.To]. Audit rows
// are narrow and the hypertable has no index on id alone, so the page is a
// direct select (no deferred join).
func PageAudit(ctx context.Context, tx pgx.Tx, tenantID string, f AuditPageFilter, req listquery.Request) ([]AuditRow, int, listquery.Request, error) {
	var a args
	where := "a.tenant_id = " + a.add(tenantID) + eqCond("a.event_type", f.EventType, &a) + eqCond("a.actor_id", f.ActorID, &a) +
		" AND a.ts >= " + a.add(f.From) + " AND a.ts <= " + a.add(f.To)
	return runPage(ctx, tx, pageQuery{cols: auditCols, from: "lcm_audit_events a", where: where}, a, AuditList, req, scanAudit)
}
