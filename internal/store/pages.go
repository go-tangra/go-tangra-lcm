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

// pageQuery names the parts of one page query; cols, from and where are
// constants, where is parameterised by args.
type pageQuery struct {
	cols  string
	from  string
	where string
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
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY %s LIMIT %d OFFSET %d",
		q.cols, q.from, q.where, req.OrderBy(spec), req.Limit(), req.Offset()), a...)
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
func PageCertificates(ctx context.Context, tx pgx.Tx, tenantID string, f CertificatePageFilter, req listquery.Request) ([]IssuedCertificate, int, listquery.Request, error) {
	var a args
	where := "c.tenant_id = " + a.add(tenantID) +
		eqCond("c.issuer_id::text", f.IssuerID, &a) + eqCond("c.spiffe_id", f.SpiffeID, &a) + eqCond("c.status", f.Status, &a) +
		visibleCond(f.Visible, "c.id", &a)
	return runPage(ctx, tx, pageQuery{cols: certPageCols, from: "issued_certificates c", where: where}, a, CertificateList, req,
		func(r pgx.Rows) (IssuedCertificate, error) { return scanCertificate(r) })
}

// PageIssuers pages the issuers v allows.
func PageIssuers(ctx context.Context, tx pgx.Tx, tenantID string, v Visible, req listquery.Request) ([]Issuer, int, listquery.Request, error) {
	var a args
	where := "i.tenant_id = " + a.add(tenantID) + visibleCond(v, "i.id", &a)
	return runPage(ctx, tx, pageQuery{cols: issuerPageCols, from: "issuers i", where: where}, a, IssuerList, req,
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
	return runPage(ctx, tx, pageQuery{cols: requestCols, from: "certificate_requests r", where: where}, a, RequestList, req,
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
	return runPage(ctx, tx, pageQuery{cols: jobCols, from: "certificate_jobs j", where: where}, a, JobList, req,
		func(r pgx.Rows) (CertificateJob, error) { return scanJob(r) })
}

// secretPageCols are the secret columns of a list page: the sealed value is
// never read for a listing (nor sortable).
const secretPageCols = "id, tenant_id, name, kind, NULL::bytea, created_by, updated_by, created_at, updated_at" // #nosec G101 -- SQL column list, not a credential

// PageSecrets pages the tenant's secrets (metadata only).
func PageSecrets(ctx context.Context, tx pgx.Tx, tenantID string, req listquery.Request) ([]TenantSecret, int, listquery.Request, error) {
	var a args
	return runPage(ctx, tx, pageQuery{cols: secretPageCols, from: "tenant_secrets s", where: "s.tenant_id = " + a.add(tenantID)}, a, SecretList, req,
		func(r pgx.Rows) (TenantSecret, error) { return scanSecret(r) })
}

// webhookPageCols are the webhook columns of a list page: the sealed signing
// secret is never read for a listing.
const webhookPageCols = "id, tenant_id, name, url, event_types, NULL::bytea, enabled, created_by, updated_by, created_at, updated_at"

// PageWebhooks pages the tenant's webhook endpoints.
func PageWebhooks(ctx context.Context, tx pgx.Tx, tenantID string, req listquery.Request) ([]WebhookEndpoint, int, listquery.Request, error) {
	var a args
	return runPage(ctx, tx, pageQuery{cols: webhookPageCols, from: "webhook_endpoints w", where: "w.tenant_id = " + a.add(tenantID)}, a, WebhookList, req,
		func(r pgx.Rows) (WebhookEndpoint, error) { return scanWebhook(r) })
}

// PageAudit pages the tenant's audit events within [f.From, f.To].
func PageAudit(ctx context.Context, tx pgx.Tx, tenantID string, f AuditPageFilter, req listquery.Request) ([]AuditRow, int, listquery.Request, error) {
	var a args
	where := "a.tenant_id = " + a.add(tenantID) + eqCond("a.event_type", f.EventType, &a) + eqCond("a.actor_id", f.ActorID, &a) +
		" AND a.ts >= " + a.add(f.From) + " AND a.ts <= " + a.add(f.To)
	return runPage(ctx, tx, pageQuery{cols: auditCols, from: "lcm_audit_events a", where: where}, a, AuditList, req, scanAudit)
}
