-- =========================================================
-- Modular Core PoC : database bootstrap
-- Multi-tenant RLS + HITL integrity
-- =========================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- provides gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------
-- Tenants
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug        text NOT NULL UNIQUE,
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------
-- Members of a tenant (used to simulate request identity)
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_members (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_email  text NOT NULL,
  role        text NOT NULL DEFAULT 'member',
  UNIQUE (tenant_id, user_email)
);

-- ---------------------------------------------------------------
-- Records: every row belongs to exactly one tenant
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS records (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title       text NOT NULL,
  body        text,
  amount      numeric(18,2) NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_records_tenant ON records (tenant_id);

-- ---------------------------------------------------------------
-- Human-in-the-loop approvals (HITL)
-- A record may only become 'approved' through an approval row
-- whose digest matches the record payload.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approvals (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  record_id     uuid NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  requested_by  text NOT NULL,
  approver      text,
  status        text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','approved','rejected')),
  payload_hash  text NOT NULL,
  decided_at    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_approvals_record ON approvals (record_id);

-- Tamper-evident log: append only, hash chained
CREATE TABLE IF NOT EXISTS audit_log (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  action       text NOT NULL,
  actor        text NOT NULL,
  payload_hash text NOT NULL,
  prev_hash    text,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------
-- Row Level Security
-- The app connects as a NON-superuser role so RLS is enforced
-- by PostgreSQL itself, not by application code.
-- ---------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'poc_app') THEN
    CREATE ROLE poc_app LOGIN PASSWORD 'pocsecret' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

GRANT CONNECT ON DATABASE modularpoc TO poc_app;

GRANT USAGE ON SCHEMA public TO poc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, tenant_members, records, approvals, audit_log TO poc_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO poc_app;

-- helper: current tenant set by the app via set_config('app.current_tenant', ...)
CREATE OR REPLACE FUNCTION app_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_tenant', true), '')::uuid
$$;

-- helper: current actor
CREATE OR REPLACE FUNCTION app_current_actor() RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_actor', true), '')
$$;

ALTER TABLE records   ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_members ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS records_tenant_isolation ON records;
CREATE POLICY records_tenant_isolation ON records
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

DROP POLICY IF EXISTS approvals_tenant_isolation ON approvals;
CREATE POLICY approvals_tenant_isolation ON approvals
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log;
CREATE POLICY audit_log_tenant_isolation ON audit_log
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

DROP POLICY IF EXISTS tenant_members_tenant_isolation ON tenant_members;
CREATE POLICY tenant_members_tenant_isolation ON tenant_members
  USING (tenant_id = app_current_tenant())
  WITH CHECK (tenant_id = app_current_tenant());

-- tenants table: a tenant can only see itself
DROP POLICY IF EXISTS tenants_self ON tenants;
CREATE POLICY tenants_self ON tenants
  USING (id = app_current_tenant());

-- ---------------------------------------------------------------
-- Trigger: block direct status change of a record without a valid
-- approved HITL approval row (defense in depth for tamper tests).
-- ---------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_record_approval() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  ok boolean;
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'approved' THEN
      SELECT EXISTS (
        SELECT 1 FROM approvals a
        WHERE a.record_id = NEW.id
          AND a.tenant_id = NEW.tenant_id
          AND a.status = 'approved'
          AND a.payload_hash = encode(digest(
                NEW.title || '|' || COALESCE(NEW.body,'') || '|' || NEW.amount::text,
                'sha256'), 'hex')
      ) INTO ok;
      IF NOT ok THEN
        RAISE EXCEPTION 'HITL violation: no matching approved approval row for record %', NEW.id
          USING ERRCODE = '42501';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$$;

ALTER TABLE records ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'draft';

DROP TRIGGER IF EXISTS trg_record_approval_guard ON records;
CREATE TRIGGER trg_record_approval_guard
  BEFORE UPDATE ON records
  FOR EACH ROW EXECUTE FUNCTION guard_record_approval();

-- audit log append-only
CREATE OR REPLACE FUNCTION guard_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only' USING ERRCODE = '42501';
END
$$;

DROP TRIGGER IF EXISTS trg_audit_append_only ON audit_log;
CREATE TRIGGER trg_audit_append_only
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION guard_audit_append_only();

-- seed tenants
INSERT INTO tenants (slug, name) VALUES
  ('acme',  'ACME Corp'),
  ('globex','Globex Inc')
ON CONFLICT (slug) DO NOTHING;
