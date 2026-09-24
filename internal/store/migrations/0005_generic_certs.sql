-- +goose Up
-- Generic (ACME/Let's-Encrypt) certificates have DNS domains, not a SPIFFE id.
ALTER TABLE issued_certificates ALTER COLUMN spiffe_id DROP NOT NULL;
ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'svid' CHECK (kind IN ('svid','generic'));
ALTER TABLE certificate_requests ALTER COLUMN spiffe_id DROP NOT NULL;
ALTER TABLE certificate_requests ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'svid' CHECK (kind IN ('svid','generic'));

-- +goose Down
ALTER TABLE issued_certificates DROP COLUMN IF EXISTS kind;
ALTER TABLE certificate_requests DROP COLUMN IF EXISTS kind;
