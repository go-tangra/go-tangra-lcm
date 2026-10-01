-- +goose NO TRANSACTION
-- +goose Up
-- Server-side tables performance (go-tangra specs/032-server-side-tables,
-- perf.md fixes 1 and 2). The list Specs mark NOT NULL sort columns NotNull,
-- so ORDER BY carries no NULLS clause and a plain ascending
-- (tenant_id, col, id) btree serves both directions (a backward scan for
-- DESC). The 0009 created_at indexes were (tenant_id, created_at DESC, id):
-- id runs against created_at, so neither direction of the default
-- newest-first page (created_at DESC, id DESC) could use them.
--
-- Built CONCURRENTLY (no write lock on large certificate tables), hence NO
-- TRANSACTION: goose runs each statement on its own. Each index is dropped
-- before it is rebuilt, which also clears an INVALID leftover of an
-- interrupted run, so the migration can simply be re-run. The old indexes
-- served no list order, so the short gap without them costs nothing.
DROP INDEX CONCURRENTLY IF EXISTS certs_tenant_created;
CREATE INDEX CONCURRENTLY certs_tenant_created ON issued_certificates (tenant_id, created_at, id);
DROP INDEX CONCURRENTLY IF EXISTS requests_tenant_created;
CREATE INDEX CONCURRENTLY requests_tenant_created ON certificate_requests (tenant_id, created_at, id);
DROP INDEX CONCURRENTLY IF EXISTS jobs_tenant_created;
CREATE INDEX CONCURRENTLY jobs_tenant_created ON certificate_jobs (tenant_id, created_at, id);
-- The issuer filter (c.issuer_id = $n::uuid, no cast on the column) with the
-- default newest-first order.
DROP INDEX CONCURRENTLY IF EXISTS certs_tenant_issuer_created;
CREATE INDEX CONCURRENTLY certs_tenant_issuer_created ON issued_certificates (tenant_id, issuer_id, created_at, id);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS certs_tenant_issuer_created;
DROP INDEX CONCURRENTLY IF EXISTS jobs_tenant_created;
CREATE INDEX CONCURRENTLY jobs_tenant_created ON certificate_jobs (tenant_id, created_at DESC, id);
DROP INDEX CONCURRENTLY IF EXISTS requests_tenant_created;
CREATE INDEX CONCURRENTLY requests_tenant_created ON certificate_requests (tenant_id, created_at DESC, id);
DROP INDEX CONCURRENTLY IF EXISTS certs_tenant_created;
CREATE INDEX CONCURRENTLY certs_tenant_created ON issued_certificates (tenant_id, created_at DESC, id);
