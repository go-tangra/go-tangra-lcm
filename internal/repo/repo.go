// Package repo declares the persistence the lcm services depend on. The
// database binding (repodb) runs every call in a tenant-scoped transaction
// under RLS; the in-memory double (memstore) applies the same tenant argument
// checks so unit tests observe identical semantics.
package repo

import (
	"context"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Issuers is the issuer persistence.
type Issuers interface {
	InsertIssuer(ctx context.Context, i store.Issuer) error
	GetIssuer(ctx context.Context, tenantID, id string) (store.Issuer, error)
	ListIssuers(ctx context.Context, tenantID, afterName string, limit int) ([]store.Issuer, error)
	IssuersByIDs(ctx context.Context, tenantID string, ids []string) ([]store.Issuer, error)
	DefaultIssuer(ctx context.Context, tenantID, trustDomain string) (store.Issuer, error)
	UpdateIssuer(ctx context.Context, i store.Issuer) error
	ClearDefaultIssuer(ctx context.Context, tenantID, trustDomain, exceptID string) error
	DeleteIssuer(ctx context.Context, tenantID, id string) error
}

// CAs is the CA / trust-bundle persistence.
type CAs interface {
	InsertCA(ctx context.Context, c store.CA) error
	GetCA(ctx context.Context, tenantID, id string) (store.CA, error)
	CAByState(ctx context.Context, tenantID, trustDomain, state string) (store.CA, error)
	CAsForDomain(ctx context.Context, tenantID, trustDomain string) ([]store.CA, error)
	SetCAState(ctx context.Context, tenantID, id, state string) error
	DeleteCA(ctx context.Context, tenantID, id string) error
}

// Requests is the certificate-request persistence.
type Requests interface {
	InsertRequest(ctx context.Context, r store.CertificateRequest) error
	GetRequest(ctx context.Context, tenantID, id string) (store.CertificateRequest, error)
	ListRequests(ctx context.Context, tenantID string, f store.RequestFilter) ([]store.CertificateRequest, error)
	SetRequestStatus(ctx context.Context, tenantID, id, status string, approver *string, reason *string) error
	CompleteRequest(ctx context.Context, tenantID, id, status string, certificateID *string, reason *string) error
	DeleteRequest(ctx context.Context, tenantID, id string) error
}

// Jobs is the certificate-job persistence.
type Jobs interface {
	InsertJob(ctx context.Context, j store.CertificateJob) error
	GetJob(ctx context.Context, tenantID, id string) (store.CertificateJob, error)
	ListJobs(ctx context.Context, tenantID string, f store.JobFilter) ([]store.CertificateJob, error)
	UpdateJob(ctx context.Context, j store.CertificateJob) error
	DeleteJob(ctx context.Context, tenantID, id string) error
	ClaimDueJobs(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]store.CertificateJob, error) // system scope
}

// Certificates is the issued-certificate persistence.
type Certificates interface {
	InsertCertificate(ctx context.Context, c store.IssuedCertificate) error
	GetCertificate(ctx context.Context, tenantID, id string) (store.IssuedCertificate, error)
	ListCertificates(ctx context.Context, tenantID string, f store.CertificateFilter) ([]store.IssuedCertificate, error)
	CertificatesByIDs(ctx context.Context, tenantID string, ids []string) ([]store.IssuedCertificate, error)
	UpdateCertificate(ctx context.Context, c store.IssuedCertificate) error
	SetCertificateStatus(ctx context.Context, tenantID, id, status string, supersededBy *string) error
	MarkKeyDelivered(ctx context.Context, tenantID, id string) error
	DeleteCertificate(ctx context.Context, tenantID, id string) error
	DueForRenewal(ctx context.Context, now, notAfterBefore time.Time, limit int) ([]store.IssuedCertificate, error) // system scope
}

// Revocations is the revocation persistence.
type Revocations interface {
	InsertRevocation(ctx context.Context, r store.Revocation) error
	ListRevocations(ctx context.Context, tenantID string, cursor time.Time, limit int) ([]store.Revocation, error)
}

// Installed is the installed-certificate persistence.
type Installed interface {
	UpsertInstalled(ctx context.Context, i store.InstalledCertificate) error
	ListInstalled(ctx context.Context, tenantID, clientID string, cursor time.Time, limit int) ([]store.InstalledCertificate, error)
}

// Targets is the deployment-target persistence.
type Targets interface {
	InsertTarget(ctx context.Context, t store.DeploymentTarget) error
	GetTarget(ctx context.Context, tenantID, id string) (store.DeploymentTarget, error)
	ListTargets(ctx context.Context, tenantID string) ([]store.DeploymentTarget, error)
	DeleteTarget(ctx context.Context, tenantID, id string) error
}

// Secrets is the tenant-secret persistence.
type Secrets interface {
	InsertSecret(ctx context.Context, s store.TenantSecret) error
	GetSecret(ctx context.Context, tenantID, id string) (store.TenantSecret, error)
	SecretByName(ctx context.Context, tenantID, name string) (store.TenantSecret, error)
	ListSecrets(ctx context.Context, tenantID string) ([]store.TenantSecret, error)
	UpdateSecret(ctx context.Context, s store.TenantSecret) error
	DeleteSecret(ctx context.Context, tenantID, id string) error
}

// Webhooks is the webhook-endpoint persistence.
type Webhooks interface {
	InsertWebhook(ctx context.Context, w store.WebhookEndpoint) error
	GetWebhook(ctx context.Context, tenantID, id string) (store.WebhookEndpoint, error)
	ListWebhooks(ctx context.Context, tenantID string) ([]store.WebhookEndpoint, error)
	WebhooksForEvent(ctx context.Context, tenantID, eventType string) ([]store.WebhookEndpoint, error)
	DeleteWebhook(ctx context.Context, tenantID, id string) error
}

// Grants is the relation-tuple persistence.
type Grants interface {
	UpsertGrant(ctx context.Context, g store.Grant) (store.Grant, error)
	GetGrant(ctx context.Context, tenantID, id string) (store.Grant, error)
	DeleteGrant(ctx context.Context, tenantID, id string) error
	GrantsOnResource(ctx context.Context, tenantID, resourceType, resourceID string) ([]store.Grant, error)
	GrantsForSubjects(ctx context.Context, tenantID, userID string, roles []string, now time.Time) ([]store.Grant, error)
	DeleteGrantsOfResource(ctx context.Context, tenantID, resourceType, resourceID string) error
}

// CertLog is the certificate-history persistence (hypertable).
type CertLog interface {
	InsertCertLog(ctx context.Context, rows []store.CertLogRow) error
}

// Audit is the audit persistence.
type Audit interface {
	InsertAuditRows(ctx context.Context, rows []store.AuditRow) error
	QueryAudit(ctx context.Context, tenantID string, f store.AuditFilter) ([]store.AuditRow, error)
}

// Stats reads the per-tenant counts.
type Stats interface {
	TenantStats(ctx context.Context, tenantID string, now time.Time, window time.Duration) (store.Stats, error)
}

// Store is everything, plus Atomic: fn runs against a Store whose writes are
// committed together or not at all.
type Store interface {
	Issuers
	CAs
	Requests
	Jobs
	Certificates
	Revocations
	Installed
	Targets
	Secrets
	Webhooks
	Grants
	CertLog
	Audit
	Stats
	Atomic(ctx context.Context, tenantID string, fn func(Store) error) error
}
