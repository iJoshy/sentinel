-- Sentinel Aurora schema (PostgreSQL / Aurora Data API)

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL UNIQUE,
  email TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_entitlements (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL UNIQUE REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  subscription_tier TEXT NOT NULL DEFAULT 'free',
  live_incident_board_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS live_monitor_configs (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL UNIQUE REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  log_groups_json TEXT NOT NULL DEFAULT '[]',
  lookback_minutes INTEGER NOT NULL DEFAULT 5,
  error_threshold INTEGER NOT NULL DEFAULT 5,
  last_polled_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id),
  title TEXT,
  source TEXT NOT NULL,
  raw_text TEXT NOT NULL,
  sanitized_text TEXT,
  guardrail_json TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  assigned_to TEXT,
  resolved_at TEXT,
  resolution_notes TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id),
  status TEXT NOT NULL,
  error_message TEXT,
  analysis_json TEXT,
  current_stage TEXT,
  pipeline_events TEXT NOT NULL DEFAULT '[]',
  similar_incidents_json TEXT,
  clarification_answers_json TEXT,
  pir_json TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS live_incidents (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  severity TEXT NOT NULL DEFAULT 'medium',
  source_log_groups_json TEXT NOT NULL DEFAULT '[]',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  event_count INTEGER NOT NULL DEFAULT 0,
  incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL,
  latest_job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_analysis_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (clerk_user_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS remediation_actions (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  action_text TEXT NOT NULL,
  action_type TEXT NOT NULL DEFAULT 'recommended',
  status TEXT NOT NULL DEFAULT 'pending',
  assigned_to TEXT,
  completed_at TEXT,
  notes TEXT,
  severity TEXT NOT NULL DEFAULT 'medium',
  confidence TEXT NOT NULL DEFAULT 'medium',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  rationale TEXT,
  risk_if_wrong TEXT,
  due_date TEXT,
  parent_action_id TEXT,
  eval_response TEXT,
  engineer_submission TEXT,
  source_anchor_action_id TEXT,
  created_at TEXT NOT NULL
);

ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS assigned_to TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS completed_at TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS due_date TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS parent_action_id TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS eval_response TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS engineer_submission TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS source_anchor_action_id TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS confidence TEXT NOT NULL DEFAULT 'medium';
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS evidence_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS rationale TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS risk_if_wrong TEXT;

CREATE TABLE IF NOT EXISTS integrations (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  config_json TEXT NOT NULL DEFAULT '{}',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  action_id TEXT NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS follow_ups (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  action_id TEXT,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  user_email TEXT NOT NULL,
  user_name TEXT,
  message TEXT,
  remind_at TEXT NOT NULL,
  sent_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_clerk_created
  ON incidents(clerk_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_jobs_incident_created
  ON jobs(incident_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_jobs_clerk_created
  ON jobs(clerk_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_user_entitlements_clerk
  ON user_entitlements(clerk_user_id);

CREATE INDEX IF NOT EXISTS idx_live_monitor_configs_clerk
  ON live_monitor_configs(clerk_user_id);

CREATE INDEX IF NOT EXISTS idx_live_incidents_clerk_seen
  ON live_incidents(clerk_user_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_remediation_job_created
  ON remediation_actions(job_id, created_at);

CREATE INDEX IF NOT EXISTS idx_followups_due
  ON follow_ups(remind_at, sent_at);

CREATE INDEX IF NOT EXISTS idx_chat_job_action_created
  ON chat_messages(job_id, action_id, created_at);
