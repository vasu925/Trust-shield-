-- TrustShield Neon PostgreSQL setup. Safe to run after the three existing tables.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS app_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(320) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES app_users(id) ON DELETE CASCADE;
ALTER TABLE investigation_cases ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES app_users(id) ON DELETE CASCADE;
ALTER TABLE evidence_metadata ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES app_users(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS scan_history_user_created_idx ON scan_history(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS investigation_cases_user_created_idx ON investigation_cases(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS evidence_metadata_user_created_idx ON evidence_metadata(user_id, created_at DESC);
