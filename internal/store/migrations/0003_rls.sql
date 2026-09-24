-- +goose Up
-- Row-level security: the application role (no BYPASSRLS) sets app.tenant_id
-- per transaction; workers (renewal scheduler, audit writer, CRL) run with
-- app.system = on.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app_tenant_matches(tid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT tid::text = current_setting('app.tenant_id', true)
      OR current_setting('app.system', true) = 'on'
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['cas','issuers','tenant_secrets','certificate_requests','issued_certificates','certificate_jobs','revocations','installed_certificates','deployment_targets','webhook_endpoints','grants','lcm_certificate_log','lcm_audit_events']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (app_tenant_matches(tenant_id)) WITH CHECK (app_tenant_matches(tenant_id))', t);
  END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
SELECT 1;
