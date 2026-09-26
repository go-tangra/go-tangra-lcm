-- +goose Up
-- ACME orders are recorded as generic certificate requests: they run
-- asynchronously (processing) and end issued (linked to the certificate) or
-- failed (with the reason). 0001 declared the status CHECK inline, so it has
-- the default name.
ALTER TABLE certificate_requests DROP CONSTRAINT IF EXISTS certificate_requests_status_check;
ALTER TABLE certificate_requests ADD CONSTRAINT certificate_requests_status_check
  CHECK (status IN ('pending','approved','rejected','issued','processing','failed'));
ALTER TABLE certificate_requests ADD COLUMN IF NOT EXISTS certificate_id uuid;

-- +goose Down
-- Best effort: rows in the new states would violate the old CHECK.
DELETE FROM certificate_requests WHERE status IN ('processing','failed');
ALTER TABLE certificate_requests DROP COLUMN IF EXISTS certificate_id;
ALTER TABLE certificate_requests DROP CONSTRAINT IF EXISTS certificate_requests_status_check;
ALTER TABLE certificate_requests ADD CONSTRAINT certificate_requests_status_check
  CHECK (status IN ('pending','approved','rejected','issued'));
