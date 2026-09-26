-- +goose Up
-- DNS-provider secrets entered in the issuer form (api_token, …) were sealed
-- but also kept readable in settings_public and returned by the issuers API.
-- Replace every stored value with the redaction marker; the sealed settings
-- keep the real value. The key list matches acme.SecretFieldKeys() plus the
-- issuer's own secret fields (checked by a test).
-- +goose StatementBegin
DO $$
DECLARE k text;
BEGIN
  PERFORM set_config('app.system', 'on', true);
  FOREACH k IN ARRAY ARRAY['acme_account_key','dns_credential','eab_hmac_key','api_token','secret_access_key','service_account_key','auth_token','password','api_key','key']
  LOOP
    UPDATE issuers
       SET settings_public = settings_public || jsonb_build_object(k, '__set__')
     WHERE settings_public ? k
       AND jsonb_typeof(settings_public -> k) = 'string'
       AND settings_public ->> k NOT IN ('', '__set__');
    UPDATE issuers
       SET settings_public = settings_public || jsonb_build_object(k, '__set__')
     WHERE settings_public ? k
       AND jsonb_typeof(settings_public -> k) = 'object';
  END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
SELECT 1;
