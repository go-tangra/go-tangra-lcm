// Package repodb binds repo.Store to the database: every call runs in a
// tenant-scoped transaction (RLS), system-scope calls (job claiming, renewal
// scan, audit writing) in a system transaction. Covered by the tagged
// integration suite.
package repodb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// DB implements repo.Store over *store.Store.
type DB struct {
	St *store.Store
	tx pgx.Tx // set inside Atomic
}

// New wraps the store.
func New(st *store.Store) *DB { return &DB{St: st} }

func (d *DB) run(ctx context.Context, scope store.Scope, fn func(tx pgx.Tx) error) error {
	if d.tx != nil {
		return fn(d.tx)
	}
	return d.St.Tx(ctx, scope, fn)
}

func (d *DB) tenant(ctx context.Context, tid string, fn func(tx pgx.Tx) error) error {
	return d.run(ctx, store.Scope{TenantID: tid}, fn)
}

func (d *DB) system(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return d.run(ctx, store.Scope{System: true}, fn)
}

// Atomic runs fn in one tenant transaction.
func (d *DB) Atomic(ctx context.Context, tenantID string, fn func(repo.Store) error) error {
	if d.tx != nil {
		return fn(d)
	}
	return d.St.Tx(ctx, store.Scope{TenantID: tenantID}, func(tx pgx.Tx) error { return fn(&DB{St: d.St, tx: tx}) })
}

// ---- issuers

func (d *DB) InsertIssuer(ctx context.Context, i store.Issuer) error {
	return d.tenant(ctx, i.TenantID, func(tx pgx.Tx) error { return store.InsertIssuer(ctx, tx, i) })
}
func (d *DB) GetIssuer(ctx context.Context, tid, id string) (out store.Issuer, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetIssuer(ctx, tx, tid, id); return err })
	return
}
func (d *DB) ListIssuers(ctx context.Context, tid, after string, limit int) (out []store.Issuer, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListIssuers(ctx, tx, tid, after, limit); return err })
	return
}
func (d *DB) IssuersByIDs(ctx context.Context, tid string, ids []string) (out []store.Issuer, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.IssuersByIDs(ctx, tx, tid, ids); return err })
	return
}
func (d *DB) DefaultIssuer(ctx context.Context, tid, trustDomain string) (out store.Issuer, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.DefaultIssuer(ctx, tx, tid, trustDomain); return err })
	return
}
func (d *DB) UpdateIssuer(ctx context.Context, i store.Issuer) error {
	return d.tenant(ctx, i.TenantID, func(tx pgx.Tx) error { return store.UpdateIssuer(ctx, tx, i) })
}
func (d *DB) ClearDefaultIssuer(ctx context.Context, tid, trustDomain, except string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.ClearDefaultIssuer(ctx, tx, tid, trustDomain, except) })
}
func (d *DB) DeleteIssuer(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteIssuer(ctx, tx, tid, id) })
}

// ---- cas

func (d *DB) InsertCA(ctx context.Context, c store.CA) error {
	return d.tenant(ctx, c.TenantID, func(tx pgx.Tx) error { return store.InsertCA(ctx, tx, c) })
}
func (d *DB) GetCA(ctx context.Context, tid, id string) (out store.CA, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetCA(ctx, tx, tid, id); return err })
	return
}
func (d *DB) CAByState(ctx context.Context, tid, trustDomain, state string) (out store.CA, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.CAByState(ctx, tx, tid, trustDomain, state); return err })
	return
}
func (d *DB) CAsForDomain(ctx context.Context, tid, trustDomain string) (out []store.CA, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.CAsForDomain(ctx, tx, tid, trustDomain); return err })
	return
}
func (d *DB) SetCAState(ctx context.Context, tid, id, state string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.SetCAState(ctx, tx, tid, id, state) })
}
func (d *DB) DeleteCA(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteCA(ctx, tx, tid, id) })
}

// ---- certificate requests

func (d *DB) InsertRequest(ctx context.Context, r store.CertificateRequest) error {
	return d.tenant(ctx, r.TenantID, func(tx pgx.Tx) error { return store.InsertRequest(ctx, tx, r) })
}
func (d *DB) GetRequest(ctx context.Context, tid, id string) (out store.CertificateRequest, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetRequest(ctx, tx, tid, id); return err })
	return
}
func (d *DB) ListRequests(ctx context.Context, tid string, f store.RequestFilter) (out []store.CertificateRequest, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListRequests(ctx, tx, tid, f); return err })
	return
}
func (d *DB) SetRequestStatus(ctx context.Context, tid, id, status string, approver, reason *string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.SetRequestStatus(ctx, tx, tid, id, status, approver, reason) })
}
func (d *DB) CompleteRequest(ctx context.Context, tid, id, status string, certificateID, reason *string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.CompleteRequest(ctx, tx, tid, id, status, certificateID, reason) })
}
func (d *DB) DeleteRequest(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteRequest(ctx, tx, tid, id) })
}

// ---- certificate jobs

func (d *DB) InsertJob(ctx context.Context, j store.CertificateJob) error {
	return d.tenant(ctx, j.TenantID, func(tx pgx.Tx) error { return store.InsertJob(ctx, tx, j) })
}
func (d *DB) GetJob(ctx context.Context, tid, id string) (out store.CertificateJob, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetJob(ctx, tx, tid, id); return err })
	return
}
func (d *DB) ListJobs(ctx context.Context, tid string, f store.JobFilter) (out []store.CertificateJob, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListJobs(ctx, tx, tid, f); return err })
	return
}
func (d *DB) UpdateJob(ctx context.Context, j store.CertificateJob) error {
	return d.tenant(ctx, j.TenantID, func(tx pgx.Tx) error { return store.UpdateJob(ctx, tx, j) })
}
func (d *DB) DeleteJob(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteJob(ctx, tx, tid, id) })
}
func (d *DB) ClaimDueJobs(ctx context.Context, now time.Time, lease time.Duration, limit int) (out []store.CertificateJob, err error) {
	err = d.system(ctx, func(tx pgx.Tx) error { out, err = store.ClaimDueJobs(ctx, tx, now, lease, limit); return err })
	return
}

// ---- issued certificates

func (d *DB) InsertCertificate(ctx context.Context, c store.IssuedCertificate) error {
	return d.tenant(ctx, c.TenantID, func(tx pgx.Tx) error { return store.InsertCertificate(ctx, tx, c) })
}
func (d *DB) GetCertificate(ctx context.Context, tid, id string) (out store.IssuedCertificate, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetCertificate(ctx, tx, tid, id); return err })
	return
}
func (d *DB) ListCertificates(ctx context.Context, tid string, f store.CertificateFilter) (out []store.IssuedCertificate, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListCertificates(ctx, tx, tid, f); return err })
	return
}
func (d *DB) CertificatesByIDs(ctx context.Context, tid string, ids []string) (out []store.IssuedCertificate, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.CertificatesByIDs(ctx, tx, tid, ids); return err })
	return
}
func (d *DB) UpdateCertificate(ctx context.Context, c store.IssuedCertificate) error {
	return d.tenant(ctx, c.TenantID, func(tx pgx.Tx) error { return store.UpdateCertificate(ctx, tx, c) })
}
func (d *DB) SetCertificateStatus(ctx context.Context, tid, id, status string, supersededBy *string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.SetCertificateStatus(ctx, tx, tid, id, status, supersededBy) })
}
func (d *DB) MarkKeyDelivered(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.MarkKeyDelivered(ctx, tx, tid, id) })
}
func (d *DB) DeleteCertificate(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteCertificate(ctx, tx, tid, id) })
}
func (d *DB) DueForRenewal(ctx context.Context, now, notAfterBefore time.Time, limit int) (out []store.IssuedCertificate, err error) {
	err = d.system(ctx, func(tx pgx.Tx) error { out, err = store.DueForRenewal(ctx, tx, now, notAfterBefore, limit); return err })
	return
}

// ---- revocations

func (d *DB) InsertRevocation(ctx context.Context, r store.Revocation) error {
	return d.tenant(ctx, r.TenantID, func(tx pgx.Tx) error { return store.InsertRevocation(ctx, tx, r) })
}
func (d *DB) ListRevocations(ctx context.Context, tid string, cursor time.Time, limit int) (out []store.Revocation, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListRevocations(ctx, tx, tid, cursor, limit); return err })
	return
}

// ---- installed certificates

func (d *DB) UpsertInstalled(ctx context.Context, i store.InstalledCertificate) error {
	return d.tenant(ctx, i.TenantID, func(tx pgx.Tx) error { return store.UpsertInstalled(ctx, tx, i) })
}
func (d *DB) ListInstalled(ctx context.Context, tid, clientID string, cursor time.Time, limit int) (out []store.InstalledCertificate, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, err = store.ListInstalled(ctx, tx, tid, clientID, cursor, limit)
		return err
	})
	return
}

// ---- deployment targets

func (d *DB) InsertTarget(ctx context.Context, t store.DeploymentTarget) error {
	return d.tenant(ctx, t.TenantID, func(tx pgx.Tx) error { return store.InsertTarget(ctx, tx, t) })
}
func (d *DB) GetTarget(ctx context.Context, tid, id string) (out store.DeploymentTarget, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetTarget(ctx, tx, tid, id); return err })
	return
}
func (d *DB) ListTargets(ctx context.Context, tid string) (out []store.DeploymentTarget, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListTargets(ctx, tx, tid); return err })
	return
}
func (d *DB) DeleteTarget(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteTarget(ctx, tx, tid, id) })
}

// ---- tenant secrets

func (d *DB) InsertSecret(ctx context.Context, s store.TenantSecret) error {
	return d.tenant(ctx, s.TenantID, func(tx pgx.Tx) error { return store.InsertSecret(ctx, tx, s) })
}
func (d *DB) GetSecret(ctx context.Context, tid, id string) (out store.TenantSecret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetSecret(ctx, tx, tid, id); return err })
	return
}
func (d *DB) SecretByName(ctx context.Context, tid, name string) (out store.TenantSecret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.SecretByName(ctx, tx, tid, name); return err })
	return
}
func (d *DB) ListSecrets(ctx context.Context, tid string) (out []store.TenantSecret, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListSecrets(ctx, tx, tid); return err })
	return
}
func (d *DB) UpdateSecret(ctx context.Context, s store.TenantSecret) error {
	return d.tenant(ctx, s.TenantID, func(tx pgx.Tx) error { return store.UpdateSecret(ctx, tx, s) })
}
func (d *DB) DeleteSecret(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteSecret(ctx, tx, tid, id) })
}

// ---- webhook endpoints

func (d *DB) InsertWebhook(ctx context.Context, w store.WebhookEndpoint) error {
	return d.tenant(ctx, w.TenantID, func(tx pgx.Tx) error { return store.InsertWebhook(ctx, tx, w) })
}
func (d *DB) GetWebhook(ctx context.Context, tid, id string) (out store.WebhookEndpoint, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetWebhook(ctx, tx, tid, id); return err })
	return
}
func (d *DB) ListWebhooks(ctx context.Context, tid string) (out []store.WebhookEndpoint, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListWebhooks(ctx, tx, tid); return err })
	return
}
func (d *DB) WebhooksForEvent(ctx context.Context, tid, eventType string) (out []store.WebhookEndpoint, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.WebhooksForEvent(ctx, tx, tid, eventType); return err })
	return
}
func (d *DB) DeleteWebhook(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteWebhook(ctx, tx, tid, id) })
}

// ---- grants

func (d *DB) UpsertGrant(ctx context.Context, g store.Grant) (out store.Grant, err error) {
	err = d.tenant(ctx, g.TenantID, func(tx pgx.Tx) error { out, err = store.UpsertGrant(ctx, tx, g); return err })
	return
}
func (d *DB) GetGrant(ctx context.Context, tid, id string) (out store.Grant, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GetGrant(ctx, tx, tid, id); return err })
	return
}
func (d *DB) DeleteGrant(ctx context.Context, tid, id string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteGrant(ctx, tx, tid, id) })
}
func (d *DB) GrantsOnResource(ctx context.Context, tid, rt, rid string) (out []store.Grant, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GrantsOnResource(ctx, tx, tid, rt, rid); return err })
	return
}
func (d *DB) GrantsForSubjects(ctx context.Context, tid, uid string, roles []string, now time.Time) (out []store.Grant, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.GrantsForSubjects(ctx, tx, tid, uid, roles, now); return err })
	return
}
func (d *DB) DeleteGrantsOfResource(ctx context.Context, tid, rt, rid string) error {
	return d.tenant(ctx, tid, func(tx pgx.Tx) error { return store.DeleteGrantsOfResource(ctx, tx, tid, rt, rid) })
}

// ---- certificate log

func (d *DB) InsertCertLog(ctx context.Context, rows []store.CertLogRow) error {
	return d.system(ctx, func(tx pgx.Tx) error { return store.InsertCertLog(ctx, tx, rows) })
}

// ---- audit & stats

func (d *DB) InsertAuditRows(ctx context.Context, rows []store.AuditRow) error {
	return d.system(ctx, func(tx pgx.Tx) error { return store.InsertAuditRows(ctx, tx, rows) })
}
func (d *DB) QueryAudit(ctx context.Context, tid string, f store.AuditFilter) (out []store.AuditRow, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.QueryAudit(ctx, tx, tid, f); return err })
	return
}
func (d *DB) TenantStats(ctx context.Context, tid string, now time.Time, window time.Duration) (out store.Stats, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error { out, err = store.TenantStats(ctx, tx, tid, now, window); return err })
	return
}

var _ repo.Store = (*DB)(nil)
