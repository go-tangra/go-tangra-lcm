-- +goose Up
-- Per-certificate auto-renew flag. The renewal scheduler only picks up
-- certificates with auto_renew = true; operators can opt a certificate out
-- (e.g. a generic ACME cert they will rotate manually). Defaults on so existing
-- and SVID certificates keep renewing.
ALTER TABLE issued_certificates ADD COLUMN IF NOT EXISTS auto_renew boolean NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE issued_certificates DROP COLUMN IF EXISTS auto_renew;
