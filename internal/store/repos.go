package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

const uuidRE = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func jsonOrEmpty(b []byte) []byte {
	if len(b) == 0 {
		return []byte("{}")
	}
	return b
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ---------------------------------------------------------------- issuers

const issuerCols = "i.id, i.tenant_id, i.name, i.type, i.trust_domain, i.is_default, i.ca_id, i.acme_directory_url, i.acme_email, i.dns_provider, i.settings_public, i.settings_sealed, i.enabled, i.created_by, i.updated_by, i.created_at, i.updated_at, (SELECT count(*) FROM issued_certificates c WHERE c.issuer_id = i.id)"

func scanIssuer(r pgx.Row) (Issuer, error) {
	var i Issuer
	err := r.Scan(&i.ID, &i.TenantID, &i.Name, &i.Type, &i.TrustDomain, &i.IsDefault, &i.CAID, &i.ACMEDirectoryURL, &i.ACMEEmail, &i.DNSProvider, &i.SettingsPublic, &i.SettingsSealed, &i.Enabled, &i.CreatedBy, &i.UpdatedBy, &i.CreatedAt, &i.UpdatedAt, &i.CertificateCount)
	return i, notFound(err)
}

func scanIssuers(rows pgx.Rows) ([]Issuer, error) {
	defer rows.Close()
	var out []Issuer
	for rows.Next() {
		i, err := scanIssuer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// InsertIssuer creates an issuer; a name clash, a second default, or a bad ca_id is ErrConflict.
func InsertIssuer(ctx context.Context, tx pgx.Tx, i Issuer) error {
	_, err := tx.Exec(ctx, `INSERT INTO issuers (id, tenant_id, name, type, trust_domain, is_default, ca_id, acme_directory_url, acme_email, dns_provider, settings_public, settings_sealed, enabled, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`,
		i.ID, i.TenantID, i.Name, i.Type, i.TrustDomain, i.IsDefault, i.CAID, i.ACMEDirectoryURL, i.ACMEEmail, i.DNSProvider, jsonOrEmpty(i.SettingsPublic), i.SettingsSealed, i.Enabled, i.CreatedBy)
	return restricted(err)
}

// GetIssuer by tenant + id.
func GetIssuer(ctx context.Context, tx pgx.Tx, tenantID, id string) (Issuer, error) {
	return scanIssuer(tx.QueryRow(ctx, "SELECT "+issuerCols+" FROM issuers i WHERE i.tenant_id = $1 AND i.id = $2", tenantID, id))
}

// ListIssuers pages by name (cursor = name of the last row seen).
func ListIssuers(ctx context.Context, tx pgx.Tx, tenantID, afterName string, limit int) ([]Issuer, error) {
	rows, err := tx.Query(ctx, "SELECT "+issuerCols+` FROM issuers i WHERE i.tenant_id = $1 AND lower(i.name) > lower($2) ORDER BY lower(i.name), i.id LIMIT $3`, tenantID, afterName, limit)
	if err != nil {
		return nil, err
	}
	return scanIssuers(rows)
}

// IssuersByIDs loads issuers by id (order by name).
func IssuersByIDs(ctx context.Context, tx pgx.Tx, tenantID string, ids []string) ([]Issuer, error) {
	rows, err := tx.Query(ctx, "SELECT "+issuerCols+" FROM issuers i WHERE i.tenant_id = $1 AND i.id = ANY($2::uuid[]) ORDER BY lower(i.name), i.id", tenantID, nonNil(ids))
	if err != nil {
		return nil, err
	}
	return scanIssuers(rows)
}

// DefaultIssuer returns the default issuer for a trust domain.
func DefaultIssuer(ctx context.Context, tx pgx.Tx, tenantID, trustDomain string) (Issuer, error) {
	return scanIssuer(tx.QueryRow(ctx, "SELECT "+issuerCols+" FROM issuers i WHERE i.tenant_id = $1 AND i.trust_domain = $2 AND i.is_default", tenantID, trustDomain))
}

// UpdateIssuer rewrites the mutable columns.
func UpdateIssuer(ctx context.Context, tx pgx.Tx, i Issuer) error {
	ct, err := tx.Exec(ctx, `UPDATE issuers SET name = $3, type = $4, trust_domain = $5, is_default = $6, ca_id = $7, acme_directory_url = $8, acme_email = $9, dns_provider = $10, settings_public = $11, settings_sealed = $12, enabled = $13, updated_by = $14, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		i.TenantID, i.ID, i.Name, i.Type, i.TrustDomain, i.IsDefault, i.CAID, i.ACMEDirectoryURL, i.ACMEEmail, i.DNSProvider, jsonOrEmpty(i.SettingsPublic), i.SettingsSealed, i.Enabled, i.UpdatedBy)
	if err != nil {
		return restricted(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearDefaultIssuer drops the default flag of every issuer of the trust domain except id.
func ClearDefaultIssuer(ctx context.Context, tx pgx.Tx, tenantID, trustDomain, exceptID string) error {
	_, err := tx.Exec(ctx, "UPDATE issuers SET is_default = false, updated_at = now() WHERE tenant_id = $1 AND trust_domain = $2 AND is_default AND id <> $3", tenantID, trustDomain, exceptID)
	return err
}

// DeleteIssuer removes an issuer; issued certificates referencing it make it ErrConflict.
func DeleteIssuer(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM issuers WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return restricted(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- cas

const caCols = "id, tenant_id, trust_domain, cert_pem, key_sealed, state, not_before, not_after, serial, created_at"

func scanCA(r pgx.Row) (CA, error) {
	var c CA
	err := r.Scan(&c.ID, &c.TenantID, &c.TrustDomain, &c.CertPEM, &c.KeySealed, &c.State, &c.NotBefore, &c.NotAfter, &c.Serial, &c.CreatedAt)
	return c, notFound(err)
}

func scanCAs(rows pgx.Rows) ([]CA, error) {
	defer rows.Close()
	var out []CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// InsertCA creates CA material; a second active CA for a domain is ErrConflict.
func InsertCA(ctx context.Context, tx pgx.Tx, c CA) error {
	_, err := tx.Exec(ctx, `INSERT INTO cas (id, tenant_id, trust_domain, cert_pem, key_sealed, state, not_before, not_after, serial)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.ID, c.TenantID, c.TrustDomain, c.CertPEM, c.KeySealed, c.State, c.NotBefore, c.NotAfter, c.Serial)
	return conflict(err)
}

// GetCA by tenant + id.
func GetCA(ctx context.Context, tx pgx.Tx, tenantID, id string) (CA, error) {
	return scanCA(tx.QueryRow(ctx, "SELECT "+caCols+" FROM cas WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// CAByState returns the newest CA for a domain in the given state.
func CAByState(ctx context.Context, tx pgx.Tx, tenantID, trustDomain, state string) (CA, error) {
	return scanCA(tx.QueryRow(ctx, "SELECT "+caCols+" FROM cas WHERE tenant_id = $1 AND trust_domain = $2 AND state = $3 ORDER BY created_at DESC LIMIT 1", tenantID, trustDomain, state))
}

// CAsForDomain lists every CA of a trust domain, newest first.
func CAsForDomain(ctx context.Context, tx pgx.Tx, tenantID, trustDomain string) ([]CA, error) {
	rows, err := tx.Query(ctx, "SELECT "+caCols+" FROM cas WHERE tenant_id = $1 AND trust_domain = $2 ORDER BY created_at DESC", tenantID, trustDomain)
	if err != nil {
		return nil, err
	}
	return scanCAs(rows)
}

// SetCAState moves a CA to a new rotation state; a second active is ErrConflict.
func SetCAState(ctx context.Context, tx pgx.Tx, tenantID, id, state string) error {
	ct, err := tx.Exec(ctx, "UPDATE cas SET state = $3 WHERE tenant_id = $1 AND id = $2", tenantID, id, state)
	if err != nil {
		return conflict(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteCA removes CA material; issuers referencing it make it ErrConflict.
func DeleteCA(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM cas WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return restricted(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- certificate requests

const requestCols = "id, tenant_id, issuer_id, spiffe_id, sans, key_type, csr_pem, validity_seconds, requested_by, requester_kind, status, approver, reason, created_at, updated_at"

func scanRequest(r pgx.Row) (CertificateRequest, error) {
	var c CertificateRequest
	err := r.Scan(&c.ID, &c.TenantID, &c.IssuerID, &c.SpiffeID, &c.SANs, &c.KeyType, &c.CSRPEM, &c.ValiditySeconds, &c.RequestedBy, &c.RequesterKind, &c.Status, &c.Approver, &c.Reason, &c.CreatedAt, &c.UpdatedAt)
	return c, notFound(err)
}

func scanRequests(rows pgx.Rows) ([]CertificateRequest, error) {
	defer rows.Close()
	var out []CertificateRequest
	for rows.Next() {
		c, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// InsertRequest creates a certificate request; a bad issuer_id is ErrConflict.
func InsertRequest(ctx context.Context, tx pgx.Tx, r CertificateRequest) error {
	_, err := tx.Exec(ctx, `INSERT INTO certificate_requests (id, tenant_id, issuer_id, spiffe_id, sans, key_type, csr_pem, validity_seconds, requested_by, requester_kind, status, approver, reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		r.ID, r.TenantID, r.IssuerID, r.SpiffeID, jsonArrayOrEmpty(r.SANs), r.KeyType, r.CSRPEM, r.ValiditySeconds, r.RequestedBy, r.RequesterKind, r.Status, r.Approver, r.Reason)
	return restricted(err)
}

// GetRequest by tenant + id.
func GetRequest(ctx context.Context, tx pgx.Tx, tenantID, id string) (CertificateRequest, error) {
	return scanRequest(tx.QueryRow(ctx, "SELECT "+requestCols+" FROM certificate_requests WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// ListRequests pages newest first under the filter; cursor = (created_at, id) of the last row seen.
func ListRequests(ctx context.Context, tx pgx.Tx, tenantID string, f RequestFilter) ([]CertificateRequest, error) {
	rows, err := tx.Query(ctx, "SELECT "+requestCols+` FROM certificate_requests WHERE tenant_id = $1 AND ($2 = '' OR status = $2)
		AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4::uuid))
		ORDER BY created_at DESC, id DESC LIMIT $5`, tenantID, f.Status, nullTime(f.CursorTS), nullIfEmpty(f.CursorID), f.Limit)
	if err != nil {
		return nil, err
	}
	return scanRequests(rows)
}

// SetRequestStatus moves a request between states, optionally recording approver/reason.
func SetRequestStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string, approver, reason *string) error {
	ct, err := tx.Exec(ctx, "UPDATE certificate_requests SET status = $3, approver = COALESCE($4, approver), reason = COALESCE($5, reason), updated_at = now() WHERE tenant_id = $1 AND id = $2",
		tenantID, id, status, approver, reason)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteRequest removes a request.
func DeleteRequest(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM certificate_requests WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- certificate jobs

const jobCols = "j.id, j.tenant_id, j.request_id, j.type, j.status, j.lease_until, j.attempts, j.max_attempts, j.result_certificate_id, j.error, j.run_after, j.created_at, j.updated_at"

func scanJob(r pgx.Row) (CertificateJob, error) {
	var j CertificateJob
	err := r.Scan(&j.ID, &j.TenantID, &j.RequestID, &j.Type, &j.Status, &j.LeaseUntil, &j.Attempts, &j.MaxAttempts, &j.ResultCertificateID, &j.Error, &j.RunAfter, &j.CreatedAt, &j.UpdatedAt)
	return j, notFound(err)
}

func scanJobs(rows pgx.Rows) ([]CertificateJob, error) {
	defer rows.Close()
	var out []CertificateJob
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// InsertJob creates a certificate job.
func InsertJob(ctx context.Context, tx pgx.Tx, j CertificateJob) error {
	_, err := tx.Exec(ctx, `INSERT INTO certificate_jobs (id, tenant_id, request_id, type, status, lease_until, attempts, max_attempts, result_certificate_id, error, run_after)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		j.ID, j.TenantID, j.RequestID, j.Type, j.Status, j.LeaseUntil, j.Attempts, j.MaxAttempts, j.ResultCertificateID, j.Error, j.RunAfter)
	return err
}

// GetJob by tenant + id.
func GetJob(ctx context.Context, tx pgx.Tx, tenantID, id string) (CertificateJob, error) {
	return scanJob(tx.QueryRow(ctx, "SELECT "+jobCols+" FROM certificate_jobs j WHERE j.tenant_id = $1 AND j.id = $2", tenantID, id))
}

// ListJobs pages newest first under the filter; cursor = (created_at, id) of the last row seen.
func ListJobs(ctx context.Context, tx pgx.Tx, tenantID string, f JobFilter) ([]CertificateJob, error) {
	rows, err := tx.Query(ctx, "SELECT "+jobCols+` FROM certificate_jobs j WHERE j.tenant_id = $1 AND ($2 = '' OR j.status = $2)
		AND ($3::timestamptz IS NULL OR (j.created_at, j.id) < ($3, $4::uuid))
		ORDER BY j.created_at DESC, j.id DESC LIMIT $5`, tenantID, f.Status, nullTime(f.CursorTS), nullIfEmpty(f.CursorID), f.Limit)
	if err != nil {
		return nil, err
	}
	return scanJobs(rows)
}

// UpdateJob rewrites the mutable columns.
func UpdateJob(ctx context.Context, tx pgx.Tx, j CertificateJob) error {
	ct, err := tx.Exec(ctx, `UPDATE certificate_jobs SET status = $3, lease_until = $4, attempts = $5, max_attempts = $6, result_certificate_id = $7, error = $8, run_after = $9, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, j.TenantID, j.ID, j.Status, j.LeaseUntil, j.Attempts, j.MaxAttempts, j.ResultCertificateID, j.Error, j.RunAfter)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteJob removes a job.
func DeleteJob(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM certificate_jobs WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimDueJobs leases due queued jobs (system scope): each row is handed to
// exactly one claimer until the lease expires.
func ClaimDueJobs(ctx context.Context, tx pgx.Tx, now time.Time, lease time.Duration, limit int) ([]CertificateJob, error) {
	rows, err := tx.Query(ctx, `WITH due AS (
			SELECT id FROM certificate_jobs WHERE status = 'queued' AND run_after <= $1 AND (lease_until IS NULL OR lease_until < $1)
			ORDER BY run_after LIMIT $3 FOR UPDATE SKIP LOCKED)
		UPDATE certificate_jobs j SET status = 'processing', lease_until = $2, attempts = j.attempts + 1, updated_at = now() FROM due WHERE j.id = due.id
		RETURNING `+jobCols, now, now.Add(lease), limit)
	if err != nil {
		return nil, err
	}
	return scanJobs(rows)
}

// ---------------------------------------------------------------- issued certificates

const certCols = "id, tenant_id, issuer_id, request_id, serial, COALESCE(spiffe_id,'') AS spiffe_id, subject, sans, not_before, not_after, fingerprint_sha256, status, cert_pem, chain_pem, key_sealed, key_delivered, superseded_by, owner, created_by, updated_by, created_at, updated_at, kind, auto_renew"

func scanCertificate(r pgx.Row) (IssuedCertificate, error) {
	var c IssuedCertificate
	err := r.Scan(&c.ID, &c.TenantID, &c.IssuerID, &c.RequestID, &c.Serial, &c.SpiffeID, &c.Subject, &c.SANs, &c.NotBefore, &c.NotAfter, &c.FingerprintSHA256, &c.Status, &c.CertPEM, &c.ChainPEM, &c.KeySealed, &c.KeyDelivered, &c.SupersededBy, &c.Owner, &c.CreatedBy, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt, &c.Kind, &c.AutoRenew)
	return c, notFound(err)
}

func scanCertificates(rows pgx.Rows) ([]IssuedCertificate, error) {
	defer rows.Close()
	var out []IssuedCertificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// InsertCertificate stores a minted certificate; a serial clash or a bad issuer_id is ErrConflict.
func defaultKind(k string) string {
	if k == "" {
		return "svid"
	}
	return k
}

func InsertCertificate(ctx context.Context, tx pgx.Tx, c IssuedCertificate) error {
	_, err := tx.Exec(ctx, `INSERT INTO issued_certificates (id, tenant_id, issuer_id, request_id, serial, spiffe_id, subject, sans, not_before, not_after, fingerprint_sha256, status, cert_pem, chain_pem, key_sealed, key_delivered, superseded_by, owner, created_by, updated_by, kind, auto_renew)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$19,$20,$21)`,
		c.ID, c.TenantID, c.IssuerID, c.RequestID, c.Serial, c.SpiffeID, c.Subject, jsonArrayOrEmpty(c.SANs), c.NotBefore, c.NotAfter, c.FingerprintSHA256, c.Status, c.CertPEM, c.ChainPEM, c.KeySealed, c.KeyDelivered, c.SupersededBy, c.Owner, c.CreatedBy, defaultKind(c.Kind), c.AutoRenew)
	return restricted(err)
}

// GetCertificate by tenant + id.
func GetCertificate(ctx context.Context, tx pgx.Tx, tenantID, id string) (IssuedCertificate, error) {
	return scanCertificate(tx.QueryRow(ctx, "SELECT "+certCols+" FROM issued_certificates WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// ListCertificates pages newest first under the filter; cursor = (created_at, id) of the last row seen.
func ListCertificates(ctx context.Context, tx pgx.Tx, tenantID string, f CertificateFilter) ([]IssuedCertificate, error) {
	rows, err := tx.Query(ctx, "SELECT "+certCols+` FROM issued_certificates WHERE tenant_id = $1
		AND ($2 = '' OR issuer_id::text = $2) AND ($3 = '' OR spiffe_id = $3) AND ($4 = '' OR status = $4)
		AND ($5::timestamptz IS NULL OR (created_at, id) < ($5, $6::uuid))
		ORDER BY created_at DESC, id DESC LIMIT $7`, tenantID, f.IssuerID, f.SpiffeID, f.Status, nullTime(f.CursorTS), nullIfEmpty(f.CursorID), f.Limit)
	if err != nil {
		return nil, err
	}
	return scanCertificates(rows)
}

// CertificatesByIDs loads certificates by id (order by created_at desc).
func CertificatesByIDs(ctx context.Context, tx pgx.Tx, tenantID string, ids []string) ([]IssuedCertificate, error) {
	rows, err := tx.Query(ctx, "SELECT "+certCols+" FROM issued_certificates WHERE tenant_id = $1 AND id = ANY($2::uuid[]) ORDER BY created_at DESC, id DESC", tenantID, nonNil(ids))
	if err != nil {
		return nil, err
	}
	return scanCertificates(rows)
}

// UpdateCertificate rewrites the mutable columns.
func UpdateCertificate(ctx context.Context, tx pgx.Tx, c IssuedCertificate) error {
	ct, err := tx.Exec(ctx, `UPDATE issued_certificates SET status = $3, chain_pem = $4, key_sealed = $5, key_delivered = $6, superseded_by = $7, owner = $8, updated_by = $9, auto_renew = $10, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, c.TenantID, c.ID, c.Status, c.ChainPEM, c.KeySealed, c.KeyDelivered, c.SupersededBy, c.Owner, c.UpdatedBy, c.AutoRenew)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetCertificateStatus moves a certificate between states, optionally recording the superseding cert.
func SetCertificateStatus(ctx context.Context, tx pgx.Tx, tenantID, id, status string, supersededBy *string) error {
	ct, err := tx.Exec(ctx, "UPDATE issued_certificates SET status = $3, superseded_by = COALESCE($4, superseded_by), updated_at = now() WHERE tenant_id = $1 AND id = $2",
		tenantID, id, status, supersededBy)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkKeyDelivered records that the private key was handed out and clears it.
func MarkKeyDelivered(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "UPDATE issued_certificates SET key_delivered = true, key_sealed = NULL, updated_at = now() WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteCertificate removes a certificate.
func DeleteCertificate(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM issued_certificates WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return restricted(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DueForRenewal selects live certificates expiring before notAfterBefore
// (system scope); rows are locked so each poll hands them out once.
func DueForRenewal(ctx context.Context, tx pgx.Tx, now, notAfterBefore time.Time, limit int) ([]IssuedCertificate, error) {
	rows, err := tx.Query(ctx, "SELECT "+certCols+` FROM issued_certificates
		WHERE status IN ('active','expiring') AND superseded_by IS NULL AND auto_renew AND not_after > $1 AND not_after <= $2
		ORDER BY not_after LIMIT $3 FOR UPDATE SKIP LOCKED`, now, notAfterBefore, limit)
	if err != nil {
		return nil, err
	}
	return scanCertificates(rows)
}

// ---------------------------------------------------------------- revocations

const revocationCols = "id, tenant_id, certificate_id, serial, reason, revoked_at, revoked_by"

func scanRevocation(r pgx.Row) (Revocation, error) {
	var v Revocation
	err := r.Scan(&v.ID, &v.TenantID, &v.CertificateID, &v.Serial, &v.Reason, &v.RevokedAt, &v.RevokedBy)
	return v, notFound(err)
}

// InsertRevocation records a revocation; a second revocation of a cert is ErrConflict.
func InsertRevocation(ctx context.Context, tx pgx.Tx, r Revocation) error {
	_, err := tx.Exec(ctx, `INSERT INTO revocations (id, tenant_id, certificate_id, serial, reason, revoked_at, revoked_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, r.ID, r.TenantID, r.CertificateID, r.Serial, r.Reason, r.RevokedAt, r.RevokedBy)
	return conflict(err)
}

// ListRevocations lists revocations newest first; cursor = revoked_at of the last row seen.
func ListRevocations(ctx context.Context, tx pgx.Tx, tenantID string, cursor time.Time, limit int) ([]Revocation, error) {
	rows, err := tx.Query(ctx, "SELECT "+revocationCols+` FROM revocations WHERE tenant_id = $1 AND ($2::timestamptz IS NULL OR revoked_at < $2)
		ORDER BY revoked_at DESC LIMIT $3`, tenantID, nullTime(cursor), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revocation
	for rows.Next() {
		v, err := scanRevocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- installed certificates

const installedCols = "id, tenant_id, certificate_id, client_id, installed_at, reported_at"

// UpsertInstalled records what a workload reports as installed, refreshing reported_at.
func UpsertInstalled(ctx context.Context, tx pgx.Tx, i InstalledCertificate) error {
	_, err := tx.Exec(ctx, `INSERT INTO installed_certificates (id, tenant_id, certificate_id, client_id, installed_at, reported_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (tenant_id, certificate_id, client_id) DO UPDATE SET reported_at = EXCLUDED.reported_at`,
		i.ID, i.TenantID, i.CertificateID, i.ClientID, i.InstalledAt, i.ReportedAt)
	return err
}

// ListInstalled lists a client's installed certificates newest report first; cursor = reported_at.
func ListInstalled(ctx context.Context, tx pgx.Tx, tenantID, clientID string, cursor time.Time, limit int) ([]InstalledCertificate, error) {
	rows, err := tx.Query(ctx, "SELECT "+installedCols+` FROM installed_certificates WHERE tenant_id = $1 AND ($2 = '' OR client_id = $2) AND ($3::timestamptz IS NULL OR reported_at < $3)
		ORDER BY reported_at DESC LIMIT $4`, tenantID, clientID, nullTime(cursor), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstalledCertificate
	for rows.Next() {
		var i InstalledCertificate
		if err := rows.Scan(&i.ID, &i.TenantID, &i.CertificateID, &i.ClientID, &i.InstalledAt, &i.ReportedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- deployment targets

const targetCols = "id, tenant_id, name, kind, config_public, config_sealed, created_by, updated_by, created_at, updated_at"

func scanTarget(r pgx.Row) (DeploymentTarget, error) {
	var t DeploymentTarget
	err := r.Scan(&t.ID, &t.TenantID, &t.Name, &t.Kind, &t.ConfigPublic, &t.ConfigSealed, &t.CreatedBy, &t.UpdatedBy, &t.CreatedAt, &t.UpdatedAt)
	return t, notFound(err)
}

// InsertTarget creates a deployment target; a name clash is ErrConflict.
func InsertTarget(ctx context.Context, tx pgx.Tx, t DeploymentTarget) error {
	_, err := tx.Exec(ctx, `INSERT INTO deployment_targets (id, tenant_id, name, kind, config_public, config_sealed, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`, t.ID, t.TenantID, t.Name, t.Kind, jsonOrEmpty(t.ConfigPublic), t.ConfigSealed, t.CreatedBy)
	return conflict(err)
}

// GetTarget by tenant + id.
func GetTarget(ctx context.Context, tx pgx.Tx, tenantID, id string) (DeploymentTarget, error) {
	return scanTarget(tx.QueryRow(ctx, "SELECT "+targetCols+" FROM deployment_targets WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// ListTargets lists a tenant's deployment targets by name.
func ListTargets(ctx context.Context, tx pgx.Tx, tenantID string) ([]DeploymentTarget, error) {
	rows, err := tx.Query(ctx, "SELECT "+targetCols+" FROM deployment_targets WHERE tenant_id = $1 ORDER BY lower(name), id LIMIT 1000", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeploymentTarget
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTarget removes a deployment target.
func DeleteTarget(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM deployment_targets WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- tenant secrets

const secretCols = "id, tenant_id, name, kind, value_sealed, created_by, updated_by, created_at, updated_at" // #nosec G101 -- SQL column list, not a credential

func scanSecret(r pgx.Row) (TenantSecret, error) {
	var s TenantSecret
	err := r.Scan(&s.ID, &s.TenantID, &s.Name, &s.Kind, &s.ValueSealed, &s.CreatedBy, &s.UpdatedBy, &s.CreatedAt, &s.UpdatedAt)
	return s, notFound(err)
}

// InsertSecret stores a tenant secret; a name clash is ErrConflict.
func InsertSecret(ctx context.Context, tx pgx.Tx, s TenantSecret) error {
	_, err := tx.Exec(ctx, `INSERT INTO tenant_secrets (id, tenant_id, name, kind, value_sealed, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$6)`, s.ID, s.TenantID, s.Name, s.Kind, s.ValueSealed, s.CreatedBy)
	return conflict(err)
}

// GetSecret by tenant + id.
func GetSecret(ctx context.Context, tx pgx.Tx, tenantID, id string) (TenantSecret, error) {
	return scanSecret(tx.QueryRow(ctx, "SELECT "+secretCols+" FROM tenant_secrets WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// SecretByName by tenant + name (case-insensitive).
func SecretByName(ctx context.Context, tx pgx.Tx, tenantID, name string) (TenantSecret, error) {
	return scanSecret(tx.QueryRow(ctx, "SELECT "+secretCols+" FROM tenant_secrets WHERE tenant_id = $1 AND lower(name) = lower($2)", tenantID, name))
}

// ListSecrets lists a tenant's secrets by name.
func ListSecrets(ctx context.Context, tx pgx.Tx, tenantID string) ([]TenantSecret, error) {
	rows, err := tx.Query(ctx, "SELECT "+secretCols+" FROM tenant_secrets WHERE tenant_id = $1 ORDER BY lower(name), id LIMIT 1000", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantSecret
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateSecret rewrites the mutable columns; a name clash is ErrConflict.
func UpdateSecret(ctx context.Context, tx pgx.Tx, s TenantSecret) error {
	ct, err := tx.Exec(ctx, "UPDATE tenant_secrets SET name = $3, kind = $4, value_sealed = $5, updated_by = $6, updated_at = now() WHERE tenant_id = $1 AND id = $2",
		s.TenantID, s.ID, s.Name, s.Kind, s.ValueSealed, s.UpdatedBy)
	if err != nil {
		return conflict(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSecret removes a tenant secret.
func DeleteSecret(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM tenant_secrets WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- webhook endpoints

const webhookCols = "id, tenant_id, name, url, event_types, secret_sealed, enabled, created_by, updated_by, created_at, updated_at"

func scanWebhook(r pgx.Row) (WebhookEndpoint, error) {
	var w WebhookEndpoint
	err := r.Scan(&w.ID, &w.TenantID, &w.Name, &w.URL, &w.EventTypes, &w.SecretSealed, &w.Enabled, &w.CreatedBy, &w.UpdatedBy, &w.CreatedAt, &w.UpdatedAt)
	if w.EventTypes == nil {
		w.EventTypes = []string{}
	}
	return w, notFound(err)
}

func scanWebhooks(rows pgx.Rows) ([]WebhookEndpoint, error) {
	defer rows.Close()
	var out []WebhookEndpoint
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// InsertWebhook creates a webhook endpoint; a name clash is ErrConflict.
func InsertWebhook(ctx context.Context, tx pgx.Tx, w WebhookEndpoint) error {
	_, err := tx.Exec(ctx, `INSERT INTO webhook_endpoints (id, tenant_id, name, url, event_types, secret_sealed, enabled, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)`, w.ID, w.TenantID, w.Name, w.URL, nonNil(w.EventTypes), w.SecretSealed, w.Enabled, w.CreatedBy)
	return conflict(err)
}

// GetWebhook by tenant + id.
func GetWebhook(ctx context.Context, tx pgx.Tx, tenantID, id string) (WebhookEndpoint, error) {
	return scanWebhook(tx.QueryRow(ctx, "SELECT "+webhookCols+" FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// ListWebhooks lists a tenant's webhook endpoints by name.
func ListWebhooks(ctx context.Context, tx pgx.Tx, tenantID string) ([]WebhookEndpoint, error) {
	rows, err := tx.Query(ctx, "SELECT "+webhookCols+" FROM webhook_endpoints WHERE tenant_id = $1 ORDER BY lower(name), id LIMIT 1000", tenantID)
	if err != nil {
		return nil, err
	}
	return scanWebhooks(rows)
}

// WebhooksForEvent lists the enabled endpoints subscribed to an event type.
func WebhooksForEvent(ctx context.Context, tx pgx.Tx, tenantID, eventType string) ([]WebhookEndpoint, error) {
	rows, err := tx.Query(ctx, "SELECT "+webhookCols+" FROM webhook_endpoints WHERE tenant_id = $1 AND enabled AND $2 = ANY(event_types) ORDER BY lower(name), id", tenantID, eventType)
	if err != nil {
		return nil, err
	}
	return scanWebhooks(rows)
}

// DeleteWebhook removes a webhook endpoint.
func DeleteWebhook(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM webhook_endpoints WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- grants

const grantCols = "id, tenant_id, resource_type, resource_id, subject_type, subject_id, relation, granted_by, granted_at, expires_at"

func scanGrant(r pgx.Row) (Grant, error) {
	var g Grant
	err := r.Scan(&g.ID, &g.TenantID, &g.ResourceType, &g.ResourceID, &g.SubjectType, &g.SubjectID, &g.Relation, &g.GrantedBy, &g.GrantedAt, &g.ExpiresAt)
	return g, notFound(err)
}

func scanGrants(rows pgx.Rows) ([]Grant, error) {
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// UpsertGrant creates or replaces the grant for (resource, subject).
func UpsertGrant(ctx context.Context, tx pgx.Tx, g Grant) (Grant, error) {
	return scanGrant(tx.QueryRow(ctx, `INSERT INTO grants (id, tenant_id, resource_type, resource_id, subject_type, subject_id, relation, granted_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (tenant_id, resource_type, resource_id, subject_type, subject_id) DO UPDATE SET relation = EXCLUDED.relation, granted_by = EXCLUDED.granted_by, granted_at = now(), expires_at = EXCLUDED.expires_at
		RETURNING `+grantCols, g.ID, g.TenantID, g.ResourceType, g.ResourceID, g.SubjectType, g.SubjectID, g.Relation, g.GrantedBy, g.ExpiresAt))
}

// GetGrant by id.
func GetGrant(ctx context.Context, tx pgx.Tx, tenantID, id string) (Grant, error) {
	return scanGrant(tx.QueryRow(ctx, "SELECT "+grantCols+" FROM grants WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// DeleteGrant revokes.
func DeleteGrant(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM grants WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// GrantsOnResource lists the grants on one resource.
func GrantsOnResource(ctx context.Context, tx pgx.Tx, tenantID, resourceType, resourceID string) ([]Grant, error) {
	rows, err := tx.Query(ctx, "SELECT "+grantCols+" FROM grants WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3 ORDER BY granted_at", tenantID, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	return scanGrants(rows)
}

// GrantsForSubjects lists unexpired grants held by any of the subjects.
func GrantsForSubjects(ctx context.Context, tx pgx.Tx, tenantID, userID string, roles []string, now time.Time) ([]Grant, error) {
	rows, err := tx.Query(ctx, "SELECT "+grantCols+` FROM grants WHERE tenant_id = $1
		AND ((subject_type = 'user' AND subject_id = $2) OR (subject_type = 'role' AND subject_id = ANY($3::text[])) OR subject_type = 'tenant')
		AND (expires_at IS NULL OR expires_at > $4) ORDER BY granted_at`, tenantID, userID, nonNil(roles), now)
	if err != nil {
		return nil, err
	}
	return scanGrants(rows)
}

// DeleteGrantsOfResource removes every grant on a resource.
func DeleteGrantsOfResource(ctx context.Context, tx pgx.Tx, tenantID, resourceType, resourceID string) error {
	_, err := tx.Exec(ctx, "DELETE FROM grants WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3", tenantID, resourceType, resourceID)
	return err
}

// ---------------------------------------------------------------- certificate log

// InsertCertLog writes a batch of certificate-history entries.
func InsertCertLog(ctx context.Context, tx pgx.Tx, rows []CertLogRow) error {
	for _, r := range rows {
		if _, err := tx.Exec(ctx, `INSERT INTO lcm_certificate_log (ts, tenant_id, certificate_id, event, issuer_id, spiffe_id, error)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, r.TS, r.TenantID, nullIfEmpty(r.CertificateID), r.Event, nullIfEmpty(r.IssuerID), r.SpiffeID, r.Error); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- audit & stats

// InsertAuditRows writes a batch.
func InsertAuditRows(ctx context.Context, tx pgx.Tx, rows []AuditRow) error {
	for _, r := range rows {
		if _, err := tx.Exec(ctx, `INSERT INTO lcm_audit_events (ts, tenant_id, event_type, actor_kind, actor_id, subject_kind, subject_id, outcome, reason, correlation_id, details)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, r.TS, r.TenantID, r.EventType, r.ActorKind, r.ActorID, r.SubjectKind, r.SubjectID, r.Outcome, r.Reason, r.CorrelationID, jsonOrEmpty(r.Details)); err != nil {
			return err
		}
	}
	return nil
}

// QueryAudit pages events newest first; cursor = ts of the last row seen. Live
// subjects resolve to a name: issuers/secrets/webhooks by name, certificates by
// spiffe id. Ids are only cast when they look like UUIDs.
func QueryAudit(ctx context.Context, tx pgx.Tx, tenantID string, f AuditFilter) ([]AuditRow, error) {
	rows, err := tx.Query(ctx, `SELECT a.ts, a.tenant_id, a.event_type, a.actor_kind, a.actor_id, a.subject_kind, a.subject_id, a.outcome, a.reason, a.correlation_id, a.details,
		COALESCE(CASE WHEN a.subject_id !~ '`+uuidRE+`' THEN NULL
			WHEN a.subject_kind = 'issuer' THEN (SELECT s.name FROM issuers s WHERE s.tenant_id = a.tenant_id AND s.id = a.subject_id::uuid)
			WHEN a.subject_kind = 'certificate' THEN (SELECT s.spiffe_id FROM issued_certificates s WHERE s.tenant_id = a.tenant_id AND s.id = a.subject_id::uuid)
			WHEN a.subject_kind = 'secret' THEN (SELECT s.name FROM tenant_secrets s WHERE s.tenant_id = a.tenant_id AND s.id = a.subject_id::uuid)
			WHEN a.subject_kind = 'webhook' THEN (SELECT s.name FROM webhook_endpoints s WHERE s.tenant_id = a.tenant_id AND s.id = a.subject_id::uuid) END, '')
		FROM lcm_audit_events a WHERE a.tenant_id = $1 AND ($2 = '' OR a.event_type = $2) AND ($3 = '' OR a.actor_id = $3)
		AND ($4::timestamptz IS NULL OR a.ts >= $4) AND ($5::timestamptz IS NULL OR a.ts <= $5) AND ($6::timestamptz IS NULL OR a.ts < $6) ORDER BY a.ts DESC LIMIT $7`,
		tenantID, f.EventType, f.ActorID, nullTime(f.From), nullTime(f.To), nullTime(f.Cursor), f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.TS, &r.TenantID, &r.EventType, &r.ActorKind, &r.ActorID, &r.SubjectKind, &r.SubjectID, &r.Outcome, &r.Reason, &r.CorrelationID, &r.Details, &r.SubjectName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TenantStats computes the per-tenant counts. The window bounds the
// expiring-soon horizon (now .. now+window) and the recent-error and
// operations look-back (now-window .. now).
func TenantStats(ctx context.Context, tx pgx.Tx, tenantID string, now time.Time, window time.Duration) (Stats, error) {
	st := Stats{Certificates: map[string]int64{}, Jobs: map[string]int64{}}
	since := now.Add(-window)
	expBefore := now.Add(window)
	if err := tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM issuers WHERE tenant_id = $1),
		(SELECT count(DISTINCT client_id) FROM installed_certificates WHERE tenant_id = $1),
		(SELECT count(*) FROM issued_certificates WHERE tenant_id = $1 AND status IN ('active','expiring') AND not_after > $2 AND not_after <= $3),
		(SELECT count(*) FROM lcm_certificate_log WHERE tenant_id = $1 AND event = 'failed' AND ts >= $4),
		(SELECT count(*) FROM lcm_audit_events WHERE tenant_id = $1 AND ts >= $4)`, tenantID, now, expBefore, since).
		Scan(&st.Issuers, &st.Clients, &st.ExpiringSoon, &st.RecentErrors, &st.Operations24h); err != nil {
		return st, err
	}
	crows, err := tx.Query(ctx, "SELECT status, count(*) FROM issued_certificates WHERE tenant_id = $1 GROUP BY status", tenantID)
	if err != nil {
		return st, err
	}
	for crows.Next() {
		var k string
		var n int64
		if err := crows.Scan(&k, &n); err != nil {
			crows.Close()
			return st, err
		}
		st.Certificates[k] = n
	}
	crows.Close()
	jrows, err := tx.Query(ctx, "SELECT status, count(*) FROM certificate_jobs WHERE tenant_id = $1 GROUP BY status", tenantID)
	if err != nil {
		return st, err
	}
	defer jrows.Close()
	for jrows.Next() {
		var k string
		var n int64
		if err := jrows.Scan(&k, &n); err != nil {
			return st, err
		}
		st.Jobs[k] = n
	}
	return st, jrows.Err()
}

// jsonArrayOrEmpty defaults an empty JSON payload to an empty array (for sans columns).
func jsonArrayOrEmpty(b []byte) []byte {
	if len(b) == 0 {
		return []byte("[]")
	}
	return b
}
