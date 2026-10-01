package store

import (
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

// List definitions of the lcm tables (go-tangra specs/032-server-side-tables,
// contracts/sortable-fields.md "lcm"). Sort fields map to constant SQL
// expressions only (the page queries alias issued_certificates as c, issuers
// as i, certificate_requests as r, certificate_jobs as j, tenant_secrets as s,
// webhook_endpoints as w and lcm_audit_events as a); the memstore sorts the
// same public names in Go. No sort field exposes sealed or secret material.
// The gRPC list RPCs (SVIDServer.Verify), the renewal scan and the backup
// walks keep their cursor queries.
var (
	// CertificateList pages GET /certificates, newest first. identity is the
	// SPIFFE ID, else the first DNS SAN, else the subject; issuer orders by
	// the issuer's name; status is the stored status.
	CertificateList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"identity":   {Expr: CertIdentityExpr, Text: true},
			"issuer":     {Expr: "(SELECT i.name FROM issuers i WHERE i.tenant_id = c.tenant_id AND i.id = c.issuer_id)", Text: true},
			"kind":       {Expr: "c.kind"},
			"status":     {Expr: "c.status"},
			"not_before": {Expr: "c.not_before", DefaultDir: listquery.Desc},
			"not_after":  {Expr: "c.not_after"},
			"created_at": {Expr: "c.created_at", DefaultDir: listquery.Desc},
		},
		Default: "created_at", TieBreak: "c.id",
	}
	// IssuerList pages GET /issuers by name.
	IssuerList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name":         {Expr: "i.name", Text: true},
			"type":         {Expr: "i.type"},
			"trust_domain": {Expr: "i.trust_domain"},
			"created_at":   {Expr: "i.created_at", DefaultDir: listquery.Desc},
		},
		Default: "name", TieBreak: "i.id",
	}
	// RequestList pages GET /requests, newest first. identity is the SPIFFE
	// ID, else the first requested domain (ACME orders).
	RequestList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"identity":   {Expr: "COALESCE(r.spiffe_id, r.sans->>0)", Text: true},
			"kind":       {Expr: "r.kind"},
			"status":     {Expr: "r.status"},
			"created_at": {Expr: "r.created_at", DefaultDir: listquery.Desc},
		},
		Default: "created_at", TieBreak: "r.id",
	}
	// JobList pages GET /jobs, newest first.
	JobList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"type":       {Expr: "j.type"},
			"status":     {Expr: "j.status"},
			"attempts":   {Expr: "j.attempts", DefaultDir: listquery.Desc},
			"run_after":  {Expr: "j.run_after", DefaultDir: listquery.Desc},
			"created_at": {Expr: "j.created_at", DefaultDir: listquery.Desc},
		},
		Default: "created_at", TieBreak: "j.id",
	}
	// SecretList pages GET /secrets by name (metadata only; the sealed value
	// is never selectable).
	SecretList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name":       {Expr: "s.name", Text: true},
			"kind":       {Expr: "s.kind"},
			"created_at": {Expr: "s.created_at", DefaultDir: listquery.Desc},
		},
		Default: "name", TieBreak: "s.id",
	}
	// WebhookList pages GET /webhooks by name.
	WebhookList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name":       {Expr: "w.name", Text: true},
			"created_at": {Expr: "w.created_at", DefaultDir: listquery.Desc},
		},
		Default: "name", TieBreak: "w.id",
	}
	// AuditList pages GET /audit, newest first, within a time window
	// (AuditWindow by default; research D6).
	AuditList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"ts": {Expr: "a.ts", DefaultDir: listquery.Desc},
		},
		Default: "ts", TieBreak: "a.id", DefaultSize: 50,
	}
)

// CertIdentityExpr is a certificate's display identity (issued_certificates c).
const CertIdentityExpr = "COALESCE(c.spiffe_id, c.sans->>0, NULLIF(c.subject, ''))"

// AuditWindow bounds an audit page without from/to so the exact count stays
// cheap on the hypertable (research D6).
const AuditWindow = 7 * 24 * time.Hour

// ListRequest completes r with the Spec's defaults (a zero Request from an
// internal caller pages with the defaults); an invalid hand-built Request
// falls back to the defaults entirely.
func ListRequest(r listquery.Request, s listquery.Spec) listquery.Request {
	out, err := listquery.New(r.Page, r.PageSize, r.Sort, r.Order, s)
	if err != nil {
		out, _ = listquery.New(0, 0, "", "", s)
	}
	return out
}

// Visible restricts a list to the records a caller may read: All (tenant
// administrators) lifts the restriction, otherwise only IDs are listed (none
// when empty). The zero value lists nothing, so a forgotten scope fails
// closed.
type Visible struct {
	All bool
	IDs []string
}

// RequestScope restricts the certificate-request and job lists to what a
// caller may read, mirroring the per-record checks of the enroll service:
//   - a request is readable by its requester (Actor, requests only), or by
//     whoever may read the issuer it is (or would be) issued from: its pinned
//     issuer (Issuers), else the default issuer of its SPIFFE ID's trust
//     domain (DefaultDomains: the trust domains whose default issuer the
//     caller may read);
//   - a job is readable through its request's issuer the same way (no
//     requester exception);
//   - AllPinned (tenant administrators) makes every pinned issuer readable;
//     AllJobs (tenant administrators) lifts the job restriction entirely.
//
// The zero value lists nothing.
type RequestScope struct {
	Actor          string
	AllPinned      bool
	Issuers        []string
	DefaultDomains []string
	AllJobs        bool
}

// CertificatePageFilter selects a certificate page.
type CertificatePageFilter struct {
	IssuerID string
	SpiffeID string
	Status   string
	Visible  Visible
}

// AuditPageFilter selects an audit page; From and To are required (the
// service applies the default window).
type AuditPageFilter struct {
	EventType string
	ActorID   string
	From, To  time.Time
}
