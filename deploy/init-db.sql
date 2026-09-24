-- Bootstrap roles/extensions for the lcm database. Table DDL lives in
-- internal/store/migrations (goose) and is applied on service start.
CREATE EXTENSION IF NOT EXISTS timescaledb;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lcm_app') THEN
    CREATE ROLE lcm_app LOGIN PASSWORD 'dev';
  END IF;
END $$;
GRANT CONNECT ON DATABASE lcm TO lcm_app;
