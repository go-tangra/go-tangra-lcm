-- +goose Up
-- Automatic-renewal back-off. A failed scheduled renewal records the failure
-- count, the next attempt and the (client-safe) reason; the scheduler skips the
-- certificate until renew_retry_at, so a broken DNS setup or an ACME refusal
-- is not retried on every tick (an ACME CA rate-limits failed validations).
-- A successful renewal supersedes the row, so its successor starts clean.
ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS renew_failures integer NOT NULL DEFAULT 0;
ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS renew_retry_at timestamptz;
ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS renew_error text;

-- +goose Down
ALTER TABLE issued_certificates DROP COLUMN IF EXISTS renew_error;
ALTER TABLE issued_certificates DROP COLUMN IF EXISTS renew_retry_at;
ALTER TABLE issued_certificates DROP COLUMN IF EXISTS renew_failures;
