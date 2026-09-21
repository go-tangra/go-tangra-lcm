-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lcm_app') THEN
    GRANT USAGE ON SCHEMA public TO lcm_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO lcm_app;
    REVOKE UPDATE, DELETE ON lcm_audit_events FROM lcm_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
SELECT 1;
