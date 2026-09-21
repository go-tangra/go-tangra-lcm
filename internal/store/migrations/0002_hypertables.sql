-- +goose Up
CREATE TABLE lcm_certificate_log (
  ts             timestamptz NOT NULL,
  tenant_id      uuid NOT NULL,
  certificate_id uuid,
  event          text NOT NULL CHECK (event IN ('issued','renewed','revoked','failed')),
  issuer_id      uuid,
  spiffe_id      text NOT NULL DEFAULT '',
  error          text NOT NULL DEFAULT ''
);
SELECT create_hypertable('lcm_certificate_log', 'ts', chunk_time_interval => INTERVAL '7 days');
CREATE INDEX lcm_cert_log_tenant ON lcm_certificate_log (tenant_id, ts DESC);
CREATE INDEX lcm_cert_log_event ON lcm_certificate_log (tenant_id, event, ts DESC);
SELECT add_retention_policy('lcm_certificate_log', INTERVAL '400 days');

CREATE TABLE lcm_audit_events (
  ts             timestamptz NOT NULL,
  tenant_id      uuid NOT NULL,
  event_type     text NOT NULL,
  actor_kind     text NOT NULL CHECK (actor_kind IN ('user','service','system')),
  actor_id       text NOT NULL DEFAULT '',
  subject_kind   text NOT NULL DEFAULT '',
  subject_id     text NOT NULL DEFAULT '',
  outcome        text NOT NULL CHECK (outcome IN ('ok','refused','failed')),
  reason         text NOT NULL DEFAULT '',
  correlation_id text NOT NULL DEFAULT '',
  details        jsonb NOT NULL DEFAULT '{}'::jsonb
);
SELECT create_hypertable('lcm_audit_events', 'ts', chunk_time_interval => INTERVAL '7 days');
CREATE INDEX lcm_audit_tenant_ts ON lcm_audit_events (tenant_id, ts DESC);
CREATE INDEX lcm_audit_type_ts ON lcm_audit_events (tenant_id, event_type, ts DESC);
CREATE INDEX lcm_audit_actor_ts ON lcm_audit_events (tenant_id, actor_id, ts DESC);
SELECT add_retention_policy('lcm_audit_events', INTERVAL '400 days');

-- +goose Down
DROP TABLE IF EXISTS lcm_audit_events;
DROP TABLE IF EXISTS lcm_certificate_log;
