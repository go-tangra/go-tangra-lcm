// Package store holds the row types and SQL bindings for the lcm database.
// Every table carries tenant_id and runs under RLS; private/credential
// material lives only in *_sealed columns and is never selected into a view.
package store

import "time"

// Issuer is a signing authority for a trust domain.
type Issuer struct {
	ID, TenantID     string
	Name             string
	Type             string // self_signed | acme
	TrustDomain      string
	IsDefault        bool
	CAID             *string
	ACMEDirectoryURL string
	ACMEEmail        string
	DNSProvider      string
	SettingsPublic   []byte // JSON, non-secret
	SettingsSealed   []byte // sealed ACME account key / DNS credential reference
	Enabled          bool
	CreatedBy        *string
	UpdatedBy        *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	CertificateCount int // joined for listings
}

// CA is root/intermediate material for a trust domain, with rotation.
type CA struct {
	ID, TenantID string
	TrustDomain  string
	CertPEM      string
	KeySealed    []byte
	State        string // active | next | retiring
	NotBefore    time.Time
	NotAfter     time.Time
	Serial       string
	CreatedAt    time.Time
}

// CertificateRequest is a pending/approved/rejected/issued application.
type CertificateRequest struct {
	ID, TenantID    string
	IssuerID        *string
	SpiffeID        string
	SANs            []byte // JSON array
	KeyType         string
	CSRPEM          *string
	ValiditySeconds int64
	RequestedBy     string
	RequesterKind   string // user | service | token
	Status          string // pending | approved | rejected | issued
	Approver        *string
	Reason          *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// RequestFilter selects certificate requests.
type RequestFilter struct {
	Status   string
	CursorTS time.Time
	CursorID string
	Limit    int
}

// CertificateJob is the async execution of a request.
type CertificateJob struct {
	ID, TenantID        string
	RequestID           string
	Type                string // issue | renew | acme
	Status              string // queued | processing | completed | failed
	LeaseUntil          *time.Time
	Attempts            int
	MaxAttempts         int
	ResultCertificateID *string
	Error               *string
	RunAfter            time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// JobFilter selects certificate jobs.
type JobFilter struct {
	Status   string
	CursorTS time.Time
	CursorID string
	Limit    int
}

// IssuedCertificate is a minted certificate/SVID.
type IssuedCertificate struct {
	ID, TenantID      string
	IssuerID          string
	Kind              string // svid | generic
	RequestID         *string
	Serial            string
	SpiffeID          string
	Subject           string
	SANs              []byte // JSON array
	NotBefore         time.Time
	NotAfter          time.Time
	FingerprintSHA256 string
	Status            string // active | expiring | expired | revoked (last two derived)
	CertPEM           string
	ChainPEM          string
	KeySealed         []byte // only when the module generated the key
	KeyDelivered      bool
	AutoRenew         bool // scheduler auto-renews only when true
	SupersededBy      *string
	Owner             string
	CreatedBy         *string
	UpdatedBy         *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// CertificateFilter selects issued certificates.
type CertificateFilter struct {
	IssuerID string
	SpiffeID string
	Status   string
	CursorTS time.Time
	CursorID string
	Limit    int
}

// Revocation feeds the CRL and the identity revocation feed.
type Revocation struct {
	ID, TenantID  string
	CertificateID string
	Serial        string
	Reason        string // RFC 5280 code
	RevokedAt     time.Time
	RevokedBy     *string
}

// InstalledCertificate is what a workload reports as installed.
type InstalledCertificate struct {
	ID, TenantID  string
	CertificateID string
	ClientID      string // workload SPIFFE id
	InstalledAt   time.Time
	ReportedAt    time.Time
}

// DeploymentTarget is a destination an operator can deploy a certificate to.
type DeploymentTarget struct {
	ID, TenantID string
	Name         string
	Kind         string // file | pull | webhook
	ConfigPublic []byte
	ConfigSealed []byte
	CreatedBy    *string
	UpdatedBy    *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TenantSecret is a per-tenant credential used by issuers/DNS providers.
type TenantSecret struct {
	ID, TenantID string
	Name         string
	Kind         string // acme_account | dns_credential
	ValueSealed  []byte // write-only; API shows "__set__"
	CreatedBy    *string
	UpdatedBy    *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// WebhookEndpoint is an external callback subscription.
type WebhookEndpoint struct {
	ID, TenantID string
	Name         string
	URL          string
	EventTypes   []string
	SecretSealed []byte // HMAC key
	Enabled      bool
	CreatedBy    *string
	UpdatedBy    *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Grant is a Zanzibar relation tuple on a certificate or issuer.
type Grant struct {
	ID, TenantID             string
	ResourceType, ResourceID string // certificate | issuer
	SubjectType, SubjectID   string // user | role | tenant ('' for tenant)
	Relation                 string // owner | editor | viewer | sharer
	GrantedBy                *string
	GrantedAt                time.Time
	ExpiresAt                *time.Time
}

// CertLogRow is one issuance/renewal/revocation history entry (hypertable).
type CertLogRow struct {
	TS            time.Time
	TenantID      string
	CertificateID string
	Event         string // issued | renewed | revoked | failed
	IssuerID      string
	SpiffeID      string
	Error         string // scrubbed
}

// AuditRow is one persisted audit event (hypertable, insert+select only).
type AuditRow struct {
	TS            time.Time
	TenantID      string
	EventType     string
	ActorKind     string // user | service | system
	ActorID       string
	SubjectKind   string // certificate | issuer | request | job | secret | grant | webhook | bundle | backup | system
	SubjectID     string
	SubjectName   string // filled on read for live subjects; writer leaves empty
	Outcome       string // ok | refused | failed
	Reason        string
	CorrelationID string
	Details       []byte // guarded: no key material or secret
}

// Stats are per-tenant counts.
type Stats struct {
	Issuers       int64
	Certificates  map[string]int64 // by status
	Jobs          map[string]int64 // by status
	Clients       int64            // distinct installed client ids
	ExpiringSoon  int64
	RecentErrors  int64 // failed cert-log entries, last 24 h
	Operations24h int64
}

// AuditFilter selects audit events.
type AuditFilter struct {
	EventType string
	ActorID   string
	From, To  time.Time
	Cursor    time.Time
	Limit     int
}
