-- +goose Up
-- Server-side tables (go-tangra specs/032-server-side-tables, research D10):
-- indexes behind the default and large sort orders of the certificate and job
-- lists, and a unique id that gives audit pages a total, stable order (events
-- can share a timestamp) under the default newest-first listing.
CREATE INDEX IF NOT EXISTS certs_tenant_created ON issued_certificates (tenant_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS certs_tenant_not_after ON issued_certificates (tenant_id, not_after, id);
CREATE INDEX IF NOT EXISTS jobs_tenant_created ON certificate_jobs (tenant_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS requests_tenant_created ON certificate_requests (tenant_id, created_at DESC, id);
ALTER TABLE lcm_audit_events ADD COLUMN IF NOT EXISTS id bigserial;
CREATE INDEX IF NOT EXISTS lcm_audit_tenant_ts_id ON lcm_audit_events (tenant_id, ts DESC, id DESC);
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lcm_app') THEN
    GRANT USAGE ON SEQUENCE lcm_audit_events_id_seq TO lcm_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP INDEX IF EXISTS lcm_audit_tenant_ts_id;
ALTER TABLE lcm_audit_events DROP COLUMN IF EXISTS id;
DROP INDEX IF EXISTS requests_tenant_created;
DROP INDEX IF EXISTS jobs_tenant_created;
DROP INDEX IF EXISTS certs_tenant_not_after;
DROP INDEX IF EXISTS certs_tenant_created;
