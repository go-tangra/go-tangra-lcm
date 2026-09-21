-- +goose Up
CREATE TABLE cas (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL,
  trust_domain text NOT NULL CHECK (length(trust_domain) BETWEEN 1 AND 253),
  cert_pem     text NOT NULL,
  key_sealed   bytea NOT NULL,
  state        text NOT NULL CHECK (state IN ('active','next','retiring')),
  not_before   timestamptz NOT NULL,
  not_after    timestamptz NOT NULL,
  serial       text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cas_domain_state ON cas (tenant_id, trust_domain, state);
CREATE UNIQUE INDEX cas_domain_active ON cas (tenant_id, trust_domain) WHERE state = 'active';

CREATE TABLE issuers (
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL,
  name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  type               text NOT NULL CHECK (type IN ('self_signed','acme')),
  trust_domain       text NOT NULL CHECK (length(trust_domain) BETWEEN 1 AND 253),
  is_default         boolean NOT NULL DEFAULT false,
  ca_id              uuid REFERENCES cas(id) ON DELETE RESTRICT,
  acme_directory_url text NOT NULL DEFAULT '',
  acme_email         text NOT NULL DEFAULT '',
  dns_provider       text NOT NULL DEFAULT '',
  settings_public    jsonb NOT NULL DEFAULT '{}'::jsonb,
  settings_sealed    bytea,
  enabled            boolean NOT NULL DEFAULT true,
  created_by         text,
  updated_by         text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX issuers_tenant_name ON issuers (tenant_id, lower(name));
CREATE UNIQUE INDEX issuers_domain_default ON issuers (tenant_id, trust_domain) WHERE is_default;

CREATE TABLE tenant_secrets (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL,
  name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  kind         text NOT NULL CHECK (kind IN ('acme_account','dns_credential')),
  value_sealed bytea NOT NULL,
  created_by   text,
  updated_by   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX secrets_tenant_name ON tenant_secrets (tenant_id, lower(name));

CREATE TABLE certificate_requests (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  issuer_id        uuid REFERENCES issuers(id) ON DELETE SET NULL,
  spiffe_id        text NOT NULL CHECK (length(spiffe_id) BETWEEN 1 AND 2048),
  sans             jsonb NOT NULL DEFAULT '[]'::jsonb,
  key_type         text NOT NULL DEFAULT '',
  csr_pem          text,
  validity_seconds bigint NOT NULL DEFAULT 0,
  requested_by     text NOT NULL DEFAULT '',
  requester_kind   text NOT NULL CHECK (requester_kind IN ('user','service','token')),
  status           text NOT NULL CHECK (status IN ('pending','approved','rejected','issued')),
  approver         text,
  reason           text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX requests_tenant_status ON certificate_requests (tenant_id, status, created_at DESC, id DESC);

CREATE TABLE issued_certificates (
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL,
  issuer_id          uuid NOT NULL REFERENCES issuers(id) ON DELETE RESTRICT,
  request_id         uuid,
  serial             text NOT NULL,
  spiffe_id          text NOT NULL CHECK (length(spiffe_id) BETWEEN 1 AND 2048),
  subject            text NOT NULL DEFAULT '',
  sans               jsonb NOT NULL DEFAULT '[]'::jsonb,
  not_before         timestamptz NOT NULL,
  not_after          timestamptz NOT NULL,
  fingerprint_sha256 text NOT NULL DEFAULT '',
  status             text NOT NULL CHECK (status IN ('active','expiring','expired','revoked')),
  cert_pem           text NOT NULL,
  chain_pem          text NOT NULL DEFAULT '',
  key_sealed         bytea,
  key_delivered      boolean NOT NULL DEFAULT false,
  superseded_by      uuid,
  owner              text NOT NULL DEFAULT '',
  created_by         text,
  updated_by         text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX certs_tenant_serial ON issued_certificates (tenant_id, serial);
CREATE INDEX certs_tenant_status_exp ON issued_certificates (tenant_id, status, not_after);
CREATE INDEX certs_tenant_spiffe ON issued_certificates (tenant_id, spiffe_id);

CREATE TABLE certificate_jobs (
  id                    uuid PRIMARY KEY,
  tenant_id             uuid NOT NULL,
  request_id            uuid NOT NULL,
  type                  text NOT NULL CHECK (type IN ('issue','renew','acme')),
  status                text NOT NULL CHECK (status IN ('queued','processing','completed','failed')),
  lease_until           timestamptz,
  attempts              integer NOT NULL DEFAULT 0,
  max_attempts          integer NOT NULL DEFAULT 5,
  result_certificate_id uuid,
  error                 text,
  run_after             timestamptz NOT NULL DEFAULT now(),
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX jobs_tenant_status ON certificate_jobs (tenant_id, status, run_after);
CREATE INDEX jobs_due ON certificate_jobs (status, run_after) WHERE status = 'queued';

CREATE TABLE revocations (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  certificate_id uuid NOT NULL,
  serial         text NOT NULL,
  reason         text NOT NULL DEFAULT 'unspecified',
  revoked_at     timestamptz NOT NULL DEFAULT now(),
  revoked_by     text
);
CREATE INDEX revocations_tenant_at ON revocations (tenant_id, revoked_at DESC);
CREATE UNIQUE INDEX revocations_cert ON revocations (tenant_id, certificate_id);

CREATE TABLE installed_certificates (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  certificate_id uuid NOT NULL,
  client_id      text NOT NULL,
  installed_at   timestamptz NOT NULL DEFAULT now(),
  reported_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, certificate_id, client_id)
);
CREATE INDEX installed_client ON installed_certificates (tenant_id, client_id, reported_at DESC);

CREATE TABLE deployment_targets (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL,
  name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  kind          text NOT NULL CHECK (kind IN ('file','pull','webhook')),
  config_public jsonb NOT NULL DEFAULT '{}'::jsonb,
  config_sealed bytea,
  created_by    text,
  updated_by    text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX targets_tenant_name ON deployment_targets (tenant_id, lower(name));

CREATE TABLE webhook_endpoints (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL,
  name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  url           text NOT NULL CHECK (length(url) <= 2048),
  event_types   text[] NOT NULL DEFAULT '{}',
  secret_sealed bytea,
  enabled       boolean NOT NULL DEFAULT true,
  created_by    text,
  updated_by    text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX webhooks_tenant_name ON webhook_endpoints (tenant_id, lower(name));

CREATE TABLE grants (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL,
  resource_type text NOT NULL CHECK (resource_type IN ('certificate','issuer')),
  resource_id   uuid NOT NULL,
  subject_type  text NOT NULL CHECK (subject_type IN ('user','role','tenant')),
  subject_id    text NOT NULL DEFAULT '',
  relation      text NOT NULL CHECK (relation IN ('owner','editor','viewer','sharer')),
  granted_by    text,
  granted_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz,
  UNIQUE (tenant_id, resource_type, resource_id, subject_type, subject_id)
);
CREATE INDEX grants_resource ON grants (tenant_id, resource_type, resource_id);
CREATE INDEX grants_subject ON grants (tenant_id, subject_type, subject_id);

-- +goose Down
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS webhook_endpoints;
DROP TABLE IF EXISTS deployment_targets;
DROP TABLE IF EXISTS installed_certificates;
DROP TABLE IF EXISTS revocations;
DROP TABLE IF EXISTS certificate_jobs;
DROP TABLE IF EXISTS issued_certificates;
DROP TABLE IF EXISTS certificate_requests;
DROP TABLE IF EXISTS tenant_secrets;
DROP TABLE IF EXISTS issuers;
DROP TABLE IF EXISTS cas;
