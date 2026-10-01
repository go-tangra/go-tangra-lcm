package repodb

import (
	"context"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// ---- list-contract pages (tenant transactions, RLS applies)

func (d *DB) PageCertificates(ctx context.Context, tid string, f store.CertificatePageFilter, req listquery.Request) (out []store.IssuedCertificate, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, total, applied, err = store.PageCertificates(ctx, tx, tid, f, req)
		return err
	})
	return
}

func (d *DB) PageIssuers(ctx context.Context, tid string, v store.Visible, req listquery.Request) (out []store.Issuer, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, total, applied, err = store.PageIssuers(ctx, tx, tid, v, req)
		return err
	})
	return
}

func (d *DB) PageRequests(ctx context.Context, tid, status string, s store.RequestScope, req listquery.Request) (out []store.CertificateRequest, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, total, applied, err = store.PageRequests(ctx, tx, tid, status, s, req)
		return err
	})
	return
}

func (d *DB) PageJobs(ctx context.Context, tid, status string, s store.RequestScope, req listquery.Request) (out []store.CertificateJob, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, total, applied, err = store.PageJobs(ctx, tx, tid, status, s, req)
		return err
	})
	return
}

func (d *DB) PageSecrets(ctx context.Context, tid string, req listquery.Request) (out []store.TenantSecret, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, total, applied, err = store.PageSecrets(ctx, tx, tid, req)
		return err
	})
	return
}

func (d *DB) PageWebhooks(ctx context.Context, tid string, req listquery.Request) (out []store.WebhookEndpoint, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, total, applied, err = store.PageWebhooks(ctx, tx, tid, req)
		return err
	})
	return
}

func (d *DB) PageAudit(ctx context.Context, tid string, f store.AuditPageFilter, req listquery.Request) (out []store.AuditRow, total int, applied listquery.Request, err error) {
	err = d.tenant(ctx, tid, func(tx pgx.Tx) error {
		out, total, applied, err = store.PageAudit(ctx, tx, tid, f, req)
		return err
	})
	return
}
