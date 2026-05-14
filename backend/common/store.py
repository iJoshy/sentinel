"""Persistence layer for Sentinel – Aurora (production) and SQLite (local)."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3

from common.config import (
    aurora_cluster_arn,
    aurora_database,
    aurora_region,
    aurora_secret_arn,
    gcp_cloudsql_connection_name,
    gcp_db_host,
    gcp_db_name,
    gcp_db_password,
    gcp_db_port,
    gcp_db_user,
    gcp_postgres_configured,
    is_local,
    sqlite_path,
)
from common.models import IncidentAnalysis


_SCHEMA_SQL = """
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
  live_incident_board_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS live_monitor_configs (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL UNIQUE REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  enabled INTEGER NOT NULL DEFAULT 1,
  log_groups_json TEXT NOT NULL DEFAULT '[]',
  lookback_minutes INTEGER NOT NULL DEFAULT 5,
  error_threshold INTEGER NOT NULL DEFAULT 5,
  last_polled_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS live_applications (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  environment TEXT NOT NULL DEFAULT 'production',
  description TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (clerk_user_id, name, environment)
);

CREATE TABLE IF NOT EXISTS live_services (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES live_applications(id) ON DELETE CASCADE,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  service_type TEXT NOT NULL DEFAULT 'service',
  criticality TEXT NOT NULL DEFAULT 'medium',
  owner TEXT,
  dependency_order INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (application_id, name)
);

CREATE TABLE IF NOT EXISTS live_log_sources (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES live_applications(id) ON DELETE CASCADE,
  service_id TEXT NOT NULL REFERENCES live_services(id) ON DELETE CASCADE,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  source_type TEXT NOT NULL DEFAULT 'log',
  source_ref TEXT NOT NULL,
  filter_query TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_cursor TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS live_log_events (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES live_applications(id) ON DELETE CASCADE,
  service_id TEXT NOT NULL REFERENCES live_services(id) ON DELETE CASCADE,
  log_source_id TEXT REFERENCES live_log_sources(id) ON DELETE SET NULL,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  event_timestamp TEXT,
  severity TEXT NOT NULL DEFAULT 'default',
  message TEXT NOT NULL,
  trace_id TEXT,
  labels_json TEXT NOT NULL DEFAULT '{}',
  payload_json TEXT NOT NULL DEFAULT '{}',
  received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS live_signals (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES live_applications(id) ON DELETE CASCADE,
  service_id TEXT NOT NULL REFERENCES live_services(id) ON DELETE CASCADE,
  log_source_id TEXT REFERENCES live_log_sources(id) ON DELETE SET NULL,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  signal_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  fingerprint TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 1,
  window_start TEXT,
  window_end TEXT,
  evidence_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (clerk_user_id, application_id, service_id, fingerprint)
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

CREATE TABLE IF NOT EXISTS integrations (
  id TEXT PRIMARY KEY,
  clerk_user_id TEXT NOT NULL REFERENCES users(clerk_user_id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  config_json TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
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
  ON incidents(clerk_user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_jobs_incident_created
  ON jobs(incident_id, created_at);

CREATE INDEX IF NOT EXISTS idx_jobs_clerk_created
  ON jobs(clerk_user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_user_entitlements_clerk
  ON user_entitlements(clerk_user_id);

CREATE INDEX IF NOT EXISTS idx_live_monitor_configs_clerk
  ON live_monitor_configs(clerk_user_id);

CREATE INDEX IF NOT EXISTS idx_live_applications_clerk
  ON live_applications(clerk_user_id, updated_at);

CREATE INDEX IF NOT EXISTS idx_live_services_app
  ON live_services(application_id, dependency_order, name);

CREATE INDEX IF NOT EXISTS idx_live_log_sources_service
  ON live_log_sources(service_id, provider);

CREATE INDEX IF NOT EXISTS idx_live_log_events_app_received
  ON live_log_events(application_id, received_at);

CREATE INDEX IF NOT EXISTS idx_live_signals_app_updated
  ON live_signals(application_id, updated_at);

CREATE INDEX IF NOT EXISTS idx_live_incidents_clerk_seen
  ON live_incidents(clerk_user_id, last_seen_at);

CREATE INDEX IF NOT EXISTS idx_remediation_job_created
  ON remediation_actions(job_id, created_at);

CREATE INDEX IF NOT EXISTS idx_followups_due
  ON follow_ups(remind_at, sent_at);

CREATE INDEX IF NOT EXISTS idx_chat_job_action_created
  ON chat_messages(job_id, action_id, created_at);
"""


class _SentinelDb:
    """All domain methods live here; subclasses provide the DB primitives."""

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _query(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

    def _query_one(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    def _execute(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> int:
        raise NotImplementedError

    def execute_script(self, statements: list[str]) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    # --- Domain methods -----------------------------------------------------

    def _ensure_user(self, clerk_user_id: str, email: str | None = None) -> None:
        uid = clerk_user_id or "anonymous"
        now = self._now_iso()
        self._execute(
            """
            INSERT INTO users (id, clerk_user_id, email, created_at, updated_at)
            VALUES (:id, :clerk_user_id, :email, :created_at, :updated_at)
            ON CONFLICT (clerk_user_id)
            DO UPDATE
              SET email = COALESCE(EXCLUDED.email, users.email),
                  updated_at = EXCLUDED.updated_at
            """,
            {
                "id": str(uuid.uuid4()),
                "clerk_user_id": uid,
                "email": email,
                "created_at": now,
                "updated_at": now,
            },
        )

    def get_user_entitlements(self, clerk_user_id: str) -> dict[str, Any]:
        uid = clerk_user_id or "anonymous"
        row = self._query_one(
            """
            SELECT subscription_tier, live_incident_board_enabled
            FROM user_entitlements
            WHERE clerk_user_id=:clerk_user_id
            """,
            {"clerk_user_id": uid},
        )
        enabled = bool((row or {}).get("live_incident_board_enabled"))
        tier = str((row or {}).get("subscription_tier") or "free").strip().lower() or "free"
        return {
            "subscription_tier": tier,
            "features": {
                "live_incident_board": enabled,
            },
        }

    def upsert_user_entitlements(
        self,
        clerk_user_id: str,
        *,
        subscription_tier: str = "free",
        live_incident_board_enabled: bool = False,
        email: str | None = None,
    ) -> None:
        uid = clerk_user_id or "anonymous"
        now = self._now_iso()
        tier = (subscription_tier or "free").strip().lower() or "free"
        self._ensure_user(uid, email=email)
        self._execute(
            """
            INSERT INTO user_entitlements (
              id, clerk_user_id, subscription_tier, live_incident_board_enabled,
              created_at, updated_at
            )
            VALUES (
              :id, :clerk_user_id, :subscription_tier, :live_incident_board_enabled,
              :created_at, :updated_at
            )
            ON CONFLICT (clerk_user_id)
            DO UPDATE
              SET subscription_tier = EXCLUDED.subscription_tier,
                  live_incident_board_enabled = EXCLUDED.live_incident_board_enabled,
                  updated_at = EXCLUDED.updated_at
            """,
            {
                "id": str(uuid.uuid4()),
                "clerk_user_id": uid,
                "subscription_tier": tier,
                "live_incident_board_enabled": live_incident_board_enabled,
                "created_at": now,
                "updated_at": now,
            },
        )

    def create_incident(
        self,
        text: str,
        title: str | None,
        source: str,
        clerk_user_id: str,
        sanitized_text: str | None = None,
        guardrail_json: dict | None = None,
    ) -> str:
        incident_id = str(uuid.uuid4())
        uid = clerk_user_id or "anonymous"
        self._ensure_user(uid)
        self._execute(
            """
            INSERT INTO incidents (
              id, clerk_user_id, title, source, raw_text, sanitized_text,
              guardrail_json, created_at
            )
            VALUES (
              :id, :clerk_user_id, :title, :source, :raw_text, :sanitized_text,
              :guardrail_json, :created_at
            )
            """,
            {
                "id": incident_id,
                "clerk_user_id": uid,
                "title": title,
                "source": source,
                "raw_text": text,
                "sanitized_text": sanitized_text,
                "guardrail_json": json.dumps(guardrail_json or {}),
                "created_at": self._now_iso(),
            },
        )
        return incident_id

    def update_incident_raw_text(
        self,
        incident_id: str,
        raw_text: str,
        *,
        title: str | None = None,
    ) -> None:
        self._execute(
            """
            UPDATE incidents
            SET raw_text=:raw_text, title=COALESCE(:title, title)
            WHERE id=:incident_id
            """,
            {
                "incident_id": incident_id,
                "raw_text": raw_text,
                "title": title,
            },
        )

    def update_incident_sanitization(
        self, incident_id: str, sanitized_text: str, guardrail_json: dict
    ) -> None:
        self._execute(
            """
            UPDATE incidents
            SET sanitized_text=:sanitized_text, guardrail_json=:guardrail_json
            WHERE id=:incident_id
            """,
            {
                "incident_id": incident_id,
                "sanitized_text": sanitized_text,
                "guardrail_json": json.dumps(guardrail_json),
            },
        )

    def create_job(
        self, incident_id: str, clerk_user_id: str, status: str = "pending"
    ) -> str:
        job_id = str(uuid.uuid4())
        uid = clerk_user_id or "anonymous"
        self._ensure_user(uid)
        self._execute(
            """
            INSERT INTO jobs (id, incident_id, clerk_user_id, status, created_at)
            VALUES (:id, :incident_id, :clerk_user_id, :status, :created_at)
            """,
            {
                "id": job_id,
                "incident_id": incident_id,
                "clerk_user_id": uid,
                "status": status,
                "created_at": self._now_iso(),
            },
        )
        return job_id

    def update_job_status(
        self, job_id: str, status: str, error_message: str | None = None
    ) -> None:
        self._execute(
            """
            UPDATE jobs
            SET status=:status, error_message=:error_message
            WHERE id=:job_id
            """,
            {"job_id": job_id, "status": status, "error_message": error_message},
        )

    def set_job_stage(self, job_id: str, stage: str, detail: str | None = None) -> None:
        payload = detail or ""
        row = self._query_one(
            "SELECT pipeline_events FROM jobs WHERE id=:job_id", {"job_id": job_id}
        )

        events: list[dict[str, Any]] = []
        raw = (row or {}).get("pipeline_events")
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    events = parsed
            except json.JSONDecodeError:
                events = []

        events.append({"stage": stage, "detail": payload, "at": self._now_iso()})

        self._execute(
            """
            UPDATE jobs
            SET current_stage=:stage, pipeline_events=:pipeline_events
            WHERE id=:job_id
            """,
            {
                "job_id": job_id,
                "stage": stage,
                "pipeline_events": json.dumps(events),
            },
        )

    def set_similar_incidents(self, job_id: str, similar: list[dict]) -> None:
        self._execute(
            "UPDATE jobs SET similar_incidents_json=:similar WHERE id=:job_id",
            {"job_id": job_id, "similar": json.dumps(similar)},
        )

    def save_analysis(self, job_id: str, analysis: IncidentAnalysis) -> None:
        self._execute(
            """
            UPDATE jobs
            SET status='completed', analysis_json=:analysis_json, completed_at=:completed_at
            WHERE id=:job_id
            """,
            {
                "job_id": job_id,
                "analysis_json": analysis.model_dump_json(),
                "completed_at": self._now_iso(),
            },
        )

    def get_incident(
        self, incident_id: str, clerk_user_id: str | None = None
    ) -> dict | None:
        if clerk_user_id:
            return self._query_one(
                "SELECT * FROM incidents WHERE id=:id AND clerk_user_id=:clerk_user_id",
                {"id": incident_id, "clerk_user_id": clerk_user_id},
            )
        return self._query_one(
            "SELECT * FROM incidents WHERE id=:id", {"id": incident_id}
        )

    def list_incidents(
        self, limit: int = 50, clerk_user_id: str | None = None
    ) -> list[dict]:
        if clerk_user_id:
            return self._query(
                """
                SELECT * FROM incidents
                WHERE clerk_user_id=:clerk_user_id
                ORDER BY created_at DESC
                LIMIT :limit
                """,
                {"clerk_user_id": clerk_user_id, "limit": limit},
            )
        return self._query(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT :limit",
            {"limit": limit},
        )

    def list_jobs(
        self, limit: int = 25, clerk_user_id: str | None = None
    ) -> list[dict[str, Any]]:
        if clerk_user_id:
            return self._query(
                """
                SELECT
                  j.id AS job_id,
                  j.incident_id,
                  j.status,
                  j.analysis_json,
                  j.created_at,
                  j.completed_at,
                  i.title,
                  i.source
                FROM jobs j
                JOIN incidents i ON i.id = j.incident_id
                WHERE j.clerk_user_id = :clerk_user_id
                ORDER BY j.created_at DESC
                LIMIT :limit
                """,
                {"clerk_user_id": clerk_user_id, "limit": limit},
            )
        return self._query(
            """
            SELECT
              j.id AS job_id,
              j.incident_id,
              j.status,
              j.analysis_json,
              j.created_at,
              j.completed_at,
              i.title,
              i.source
            FROM jobs j
            JOIN incidents i ON i.id = j.incident_id
            ORDER BY j.created_at DESC
            LIMIT :limit
            """,
            {"limit": limit},
        )

    def get_job(self, job_id: str, clerk_user_id: str | None = None) -> dict | None:
        if clerk_user_id:
            return self._query_one(
                "SELECT * FROM jobs WHERE id=:id AND clerk_user_id=:clerk_user_id",
                {"id": job_id, "clerk_user_id": clerk_user_id},
            )
        return self._query_one("SELECT * FROM jobs WHERE id=:id", {"id": job_id})

    def get_job_with_incident(
        self, job_id: str, clerk_user_id: str | None = None
    ) -> dict | None:
        if clerk_user_id:
            return self._query_one(
                """
                SELECT j.*, i.raw_text, i.title, i.source, i.sanitized_text, i.guardrail_json
                FROM jobs j
                JOIN incidents i ON i.id = j.incident_id
                WHERE j.id = :job_id AND j.clerk_user_id = :clerk_user_id
                """,
                {"job_id": job_id, "clerk_user_id": clerk_user_id},
            )
        return self._query_one(
            """
            SELECT j.*, i.raw_text, i.title, i.source, i.sanitized_text, i.guardrail_json
            FROM jobs j
            JOIN incidents i ON i.id = j.incident_id
            WHERE j.id = :job_id
            """,
            {"job_id": job_id},
        )

    def get_latest_job_for_incident(self, incident_id: str) -> dict | None:
        return self._query_one(
            """
            SELECT * FROM jobs
            WHERE incident_id=:incident_id
            ORDER BY created_at DESC
            LIMIT 1
            """,
            {"incident_id": incident_id},
        )

    def update_incident_status(
        self,
        incident_id: str,
        status: str,
        clerk_user_id: str | None = None,
    ) -> bool:
        resolved_at = self._now_iso() if status == "resolved" else None
        if clerk_user_id:
            updated = self._execute(
                """
                UPDATE incidents
                SET status=:status, resolved_at=COALESCE(:resolved_at, resolved_at)
                WHERE id=:incident_id AND clerk_user_id=:clerk_user_id
                """,
                {
                    "status": status,
                    "resolved_at": resolved_at,
                    "incident_id": incident_id,
                    "clerk_user_id": clerk_user_id,
                },
            )
        else:
            updated = self._execute(
                """
                UPDATE incidents
                SET status=:status, resolved_at=COALESCE(:resolved_at, resolved_at)
                WHERE id=:incident_id
                """,
                {
                    "status": status,
                    "resolved_at": resolved_at,
                    "incident_id": incident_id,
                },
            )
        return updated > 0

    def get_live_monitor_config(self, clerk_user_id: str) -> dict[str, Any]:
        uid = clerk_user_id or "anonymous"
        row = self._query_one(
            """
            SELECT enabled, log_groups_json, lookback_minutes, error_threshold, last_polled_at
            FROM live_monitor_configs
            WHERE clerk_user_id=:clerk_user_id
            """,
            {"clerk_user_id": uid},
        )
        log_groups: list[str] = []
        raw = (row or {}).get("log_groups_json")
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    log_groups = [str(item).strip() for item in parsed if str(item).strip()]
            except json.JSONDecodeError:
                log_groups = []
        return {
            "enabled": True if row is None else bool(row.get("enabled")),
            "log_groups": log_groups,
            "lookback_minutes": int((row or {}).get("lookback_minutes") or 5),
            "error_threshold": int((row or {}).get("error_threshold") or 5),
            "last_polled_at": (row or {}).get("last_polled_at"),
        }

    def upsert_live_monitor_config(
        self,
        clerk_user_id: str,
        *,
        enabled: bool = True,
        log_groups: list[str] | None = None,
        lookback_minutes: int = 5,
        error_threshold: int = 5,
    ) -> dict[str, Any]:
        uid = clerk_user_id or "anonymous"
        now = self._now_iso()
        self._ensure_user(uid)
        cleaned_groups = [str(item).strip() for item in (log_groups or []) if str(item).strip()]
        self._execute(
            """
            INSERT INTO live_monitor_configs (
              id, clerk_user_id, enabled, log_groups_json, lookback_minutes,
              error_threshold, created_at, updated_at
            )
            VALUES (
              :id, :clerk_user_id, :enabled, :log_groups_json, :lookback_minutes,
              :error_threshold, :created_at, :updated_at
            )
            ON CONFLICT (clerk_user_id)
            DO UPDATE
              SET enabled = EXCLUDED.enabled,
                  log_groups_json = EXCLUDED.log_groups_json,
                  lookback_minutes = EXCLUDED.lookback_minutes,
                  error_threshold = EXCLUDED.error_threshold,
                  updated_at = EXCLUDED.updated_at
            """,
            {
                "id": str(uuid.uuid4()),
                "clerk_user_id": uid,
                "enabled": enabled,
                "log_groups_json": json.dumps(cleaned_groups),
                "lookback_minutes": lookback_minutes,
                "error_threshold": error_threshold,
                "created_at": now,
                "updated_at": now,
            },
        )
        return self.get_live_monitor_config(uid)

    @staticmethod
    def _decode_json_object(raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if not raw:
            return {}
        try:
            parsed = json.loads(str(raw))
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _live_log_source_view(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "application_id": row["application_id"],
            "service_id": row["service_id"],
            "provider": row.get("provider") or "gcp_cloud_logging",
            "source_type": row.get("source_type") or "log",
            "source_ref": row.get("source_ref") or "",
            "filter_query": row.get("filter_query"),
            "enabled": bool(row.get("enabled", True)),
            "last_cursor": row.get("last_cursor"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
        }

    def _live_service_view(self, row: dict[str, Any], sources: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return {
            "id": row["id"],
            "application_id": row["application_id"],
            "name": row.get("name") or "",
            "service_type": row.get("service_type") or "service",
            "criticality": row.get("criticality") or "medium",
            "owner": row.get("owner"),
            "dependency_order": int(row.get("dependency_order") or 0),
            "metadata": self._decode_json_object(row.get("metadata_json")),
            "enabled": bool(row.get("enabled", True)),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "log_sources": sources or [],
        }

    def _live_application_view(
        self,
        row: dict[str, Any],
        services: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row.get("name") or "",
            "environment": row.get("environment") or "production",
            "description": row.get("description"),
            "enabled": bool(row.get("enabled", True)),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "services": services or [],
        }

    def create_live_application(
        self,
        clerk_user_id: str,
        *,
        name: str,
        environment: str = "production",
        description: str | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        uid = clerk_user_id or "anonymous"
        now = self._now_iso()
        app_id = str(uuid.uuid4())
        self._ensure_user(uid)
        self._execute(
            """
            INSERT INTO live_applications (
              id, clerk_user_id, name, environment, description, enabled, created_at, updated_at
            )
            VALUES (
              :id, :clerk_user_id, :name, :environment, :description, :enabled, :created_at, :updated_at
            )
            ON CONFLICT (clerk_user_id, name, environment)
            DO UPDATE
              SET description = EXCLUDED.description,
                  enabled = EXCLUDED.enabled,
                  updated_at = EXCLUDED.updated_at
            """,
            {
                "id": app_id,
                "clerk_user_id": uid,
                "name": name.strip(),
                "environment": (environment or "production").strip(),
                "description": description,
                "enabled": enabled,
                "created_at": now,
                "updated_at": now,
            },
        )
        row = self._query_one(
            """
            SELECT * FROM live_applications
            WHERE clerk_user_id=:clerk_user_id AND name=:name AND environment=:environment
            """,
            {"clerk_user_id": uid, "name": name.strip(), "environment": (environment or "production").strip()},
        )
        return self._live_application_view(row or {"id": app_id, "name": name, "environment": environment})

    def update_live_application(
        self,
        application_id: str,
        clerk_user_id: str,
        *,
        name: str | None = None,
        environment: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
    ) -> dict[str, Any] | None:
        current = self.get_live_application(application_id, clerk_user_id, include_children=False)
        if not current:
            return None
        self._execute(
            """
            UPDATE live_applications
            SET name=COALESCE(:name, name),
                environment=COALESCE(:environment, environment),
                description=COALESCE(:description, description),
                enabled=COALESCE(:enabled, enabled),
                updated_at=:updated_at
            WHERE id=:id AND clerk_user_id=:clerk_user_id
            """,
            {
                "id": application_id,
                "clerk_user_id": clerk_user_id or "anonymous",
                "name": name.strip() if name is not None else None,
                "environment": environment.strip() if environment is not None else None,
                "description": description,
                "enabled": enabled,
                "updated_at": self._now_iso(),
            },
        )
        return self.get_live_application(application_id, clerk_user_id)

    def get_live_application(
        self,
        application_id: str,
        clerk_user_id: str,
        *,
        include_children: bool = True,
    ) -> dict[str, Any] | None:
        row = self._query_one(
            """
            SELECT * FROM live_applications
            WHERE id=:id AND clerk_user_id=:clerk_user_id
            """,
            {"id": application_id, "clerk_user_id": clerk_user_id or "anonymous"},
        )
        if not row:
            return None
        if not include_children:
            return self._live_application_view(row)
        services = self.list_live_services(application_id, clerk_user_id)
        return self._live_application_view(row, services)

    def get_live_application_owner(self, application_id: str) -> str | None:
        row = self._query_one(
            "SELECT clerk_user_id FROM live_applications WHERE id=:id",
            {"id": application_id},
        )
        return str(row["clerk_user_id"]) if row and row.get("clerk_user_id") else None

    def list_live_applications(self, clerk_user_id: str) -> list[dict[str, Any]]:
        rows = self._query(
            """
            SELECT * FROM live_applications
            WHERE clerk_user_id=:clerk_user_id
            ORDER BY updated_at DESC, name ASC
            """,
            {"clerk_user_id": clerk_user_id or "anonymous"},
        )
        return [self._live_application_view(row, self.list_live_services(row["id"], clerk_user_id)) for row in rows]

    def create_live_service(
        self,
        application_id: str,
        clerk_user_id: str,
        *,
        name: str,
        service_type: str = "service",
        criticality: str = "medium",
        owner: str | None = None,
        dependency_order: int = 0,
        metadata: dict[str, Any] | None = None,
        enabled: bool = True,
    ) -> dict[str, Any] | None:
        uid = clerk_user_id or "anonymous"
        if not self.get_live_application(application_id, uid, include_children=False):
            return None
        now = self._now_iso()
        service_id = str(uuid.uuid4())
        self._execute(
            """
            INSERT INTO live_services (
              id, application_id, clerk_user_id, name, service_type, criticality,
              owner, dependency_order, metadata_json, enabled, created_at, updated_at
            )
            VALUES (
              :id, :application_id, :clerk_user_id, :name, :service_type, :criticality,
              :owner, :dependency_order, :metadata_json, :enabled, :created_at, :updated_at
            )
            ON CONFLICT (application_id, name)
            DO UPDATE
              SET service_type = EXCLUDED.service_type,
                  criticality = EXCLUDED.criticality,
                  owner = EXCLUDED.owner,
                  dependency_order = EXCLUDED.dependency_order,
                  metadata_json = EXCLUDED.metadata_json,
                  enabled = EXCLUDED.enabled,
                  updated_at = EXCLUDED.updated_at
            """,
            {
                "id": service_id,
                "application_id": application_id,
                "clerk_user_id": uid,
                "name": name.strip(),
                "service_type": (service_type or "service").strip(),
                "criticality": (criticality or "medium").strip(),
                "owner": owner,
                "dependency_order": dependency_order,
                "metadata_json": json.dumps(metadata or {}),
                "enabled": enabled,
                "created_at": now,
                "updated_at": now,
            },
        )
        row = self._query_one(
            """
            SELECT * FROM live_services
            WHERE application_id=:application_id AND name=:name AND clerk_user_id=:clerk_user_id
            """,
            {"application_id": application_id, "name": name.strip(), "clerk_user_id": uid},
        )
        return self._live_service_view(row or {"id": service_id, "application_id": application_id, "name": name})

    def list_live_services(self, application_id: str, clerk_user_id: str) -> list[dict[str, Any]]:
        rows = self._query(
            """
            SELECT * FROM live_services
            WHERE application_id=:application_id AND clerk_user_id=:clerk_user_id
            ORDER BY dependency_order ASC, name ASC
            """,
            {"application_id": application_id, "clerk_user_id": clerk_user_id or "anonymous"},
        )
        return [self._live_service_view(row, self.list_live_log_sources(row["id"], clerk_user_id)) for row in rows]

    def create_live_log_source(
        self,
        service_id: str,
        clerk_user_id: str,
        *,
        provider: str,
        source_type: str = "log",
        source_ref: str,
        filter_query: str | None = None,
        enabled: bool = True,
    ) -> dict[str, Any] | None:
        uid = clerk_user_id or "anonymous"
        service = self._query_one(
            """
            SELECT * FROM live_services
            WHERE id=:service_id AND clerk_user_id=:clerk_user_id
            """,
            {"service_id": service_id, "clerk_user_id": uid},
        )
        if not service:
            return None
        now = self._now_iso()
        source_id = str(uuid.uuid4())
        self._execute(
            """
            INSERT INTO live_log_sources (
              id, application_id, service_id, clerk_user_id, provider, source_type,
              source_ref, filter_query, enabled, created_at, updated_at
            )
            VALUES (
              :id, :application_id, :service_id, :clerk_user_id, :provider, :source_type,
              :source_ref, :filter_query, :enabled, :created_at, :updated_at
            )
            """,
            {
                "id": source_id,
                "application_id": service["application_id"],
                "service_id": service_id,
                "clerk_user_id": uid,
                "provider": provider,
                "source_type": source_type or "log",
                "source_ref": source_ref.strip(),
                "filter_query": filter_query,
                "enabled": enabled,
                "created_at": now,
                "updated_at": now,
            },
        )
        row = self._query_one("SELECT * FROM live_log_sources WHERE id=:id", {"id": source_id})
        return self._live_log_source_view(row or {"id": source_id, "application_id": service["application_id"], "service_id": service_id})

    def list_live_log_sources(self, service_id: str, clerk_user_id: str) -> list[dict[str, Any]]:
        rows = self._query(
            """
            SELECT * FROM live_log_sources
            WHERE service_id=:service_id AND clerk_user_id=:clerk_user_id
            ORDER BY created_at ASC
            """,
            {"service_id": service_id, "clerk_user_id": clerk_user_id or "anonymous"},
        )
        return [self._live_log_source_view(row) for row in rows]

    def get_live_service(self, service_id: str, clerk_user_id: str) -> dict[str, Any] | None:
        row = self._query_one(
            """
            SELECT * FROM live_services
            WHERE id=:service_id AND clerk_user_id=:clerk_user_id
            """,
            {"service_id": service_id, "clerk_user_id": clerk_user_id or "anonymous"},
        )
        if not row:
            return None
        return self._live_service_view(row, self.list_live_log_sources(service_id, clerk_user_id))

    def get_live_log_source(self, log_source_id: str, clerk_user_id: str) -> dict[str, Any] | None:
        row = self._query_one(
            """
            SELECT * FROM live_log_sources
            WHERE id=:log_source_id AND clerk_user_id=:clerk_user_id
            """,
            {"log_source_id": log_source_id, "clerk_user_id": clerk_user_id or "anonymous"},
        )
        return self._live_log_source_view(row) if row else None

    def find_live_log_source_for_event(
        self,
        application_id: str,
        clerk_user_id: str,
        *,
        provider: str,
        service_name: str | None = None,
        log_source_id: str | None = None,
    ) -> dict[str, Any] | None:
        uid = clerk_user_id or "anonymous"
        if log_source_id:
            source = self.get_live_log_source(log_source_id, uid)
            if source and source["application_id"] == application_id:
                return source
        rows = self._query(
            """
            SELECT
              s.id AS service_id,
              s.name AS service_name,
              ls.*
            FROM live_log_sources ls
            JOIN live_services s ON s.id = ls.service_id
            WHERE ls.application_id=:application_id
              AND ls.clerk_user_id=:clerk_user_id
              AND ls.provider=:provider
              AND ls.enabled = :enabled
            ORDER BY s.dependency_order ASC, s.name ASC
            """,
            {
                "application_id": application_id,
                "clerk_user_id": uid,
                "provider": provider,
                "enabled": True,
            },
        )
        if not rows:
            return None
        if service_name:
            needle = service_name.strip().lower()
            for row in rows:
                ref = str(row.get("source_ref") or "").lower()
                filt = str(row.get("filter_query") or "").lower()
                svc_name = str(row.get("service_name") or "").lower()
                if needle and (needle == svc_name or needle in ref or needle in filt):
                    return self._live_log_source_view(row)
        return self._live_log_source_view(rows[0])

    def create_live_log_event(
        self,
        *,
        application_id: str,
        service_id: str,
        clerk_user_id: str,
        provider: str,
        message: str,
        severity: str = "default",
        log_source_id: str | None = None,
        event_timestamp: str | None = None,
        trace_id: str | None = None,
        labels: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event_id = str(uuid.uuid4())
        received_at = self._now_iso()
        self._execute(
            """
            INSERT INTO live_log_events (
              id, application_id, service_id, log_source_id, clerk_user_id, provider,
              event_timestamp, severity, message, trace_id, labels_json, payload_json, received_at
            )
            VALUES (
              :id, :application_id, :service_id, :log_source_id, :clerk_user_id, :provider,
              :event_timestamp, :severity, :message, :trace_id, :labels_json, :payload_json, :received_at
            )
            """,
            {
                "id": event_id,
                "application_id": application_id,
                "service_id": service_id,
                "log_source_id": log_source_id,
                "clerk_user_id": clerk_user_id or "anonymous",
                "provider": provider,
                "event_timestamp": event_timestamp,
                "severity": (severity or "default").lower(),
                "message": message,
                "trace_id": trace_id,
                "labels_json": json.dumps(labels or {}),
                "payload_json": json.dumps(payload or {}),
                "received_at": received_at,
            },
        )
        return {
            "id": event_id,
            "application_id": application_id,
            "service_id": service_id,
            "log_source_id": log_source_id,
            "provider": provider,
            "event_timestamp": event_timestamp,
            "severity": (severity or "default").lower(),
            "message": message,
            "trace_id": trace_id,
            "received_at": received_at,
        }

    def upsert_live_signal(
        self,
        *,
        application_id: str,
        service_id: str,
        clerk_user_id: str,
        signal_type: str,
        severity: str,
        fingerprint: str,
        evidence: list[dict[str, Any]],
        log_source_id: str | None = None,
        window_start: str | None = None,
        window_end: str | None = None,
    ) -> dict[str, Any]:
        uid = clerk_user_id or "anonymous"
        now = self._now_iso()
        existing = self._query_one(
            """
            SELECT * FROM live_signals
            WHERE clerk_user_id=:clerk_user_id
              AND application_id=:application_id
              AND service_id=:service_id
              AND fingerprint=:fingerprint
            """,
            {
                "clerk_user_id": uid,
                "application_id": application_id,
                "service_id": service_id,
                "fingerprint": fingerprint,
            },
        )
        if existing:
            prior = []
            try:
                parsed = json.loads(existing.get("evidence_json") or "[]")
                if isinstance(parsed, list):
                    prior = parsed
            except json.JSONDecodeError:
                prior = []
            merged_evidence = (prior + evidence)[-12:]
            self._execute(
                """
                UPDATE live_signals
                SET severity=:severity,
                    event_count=:event_count,
                    window_start=COALESCE(:window_start, window_start),
                    window_end=:window_end,
                    evidence_json=:evidence_json,
                    status='open',
                    updated_at=:updated_at
                WHERE id=:id
                """,
                {
                    "id": existing["id"],
                    "severity": severity,
                    "event_count": int(existing.get("event_count") or 0) + max(1, len(evidence)),
                    "window_start": window_start,
                    "window_end": window_end or now,
                    "evidence_json": json.dumps(merged_evidence),
                    "updated_at": now,
                },
            )
            signal_id = existing["id"]
        else:
            signal_id = str(uuid.uuid4())
            self._execute(
                """
                INSERT INTO live_signals (
                  id, application_id, service_id, log_source_id, clerk_user_id,
                  signal_type, severity, fingerprint, event_count, window_start, window_end,
                  evidence_json, status, created_at, updated_at
                )
                VALUES (
                  :id, :application_id, :service_id, :log_source_id, :clerk_user_id,
                  :signal_type, :severity, :fingerprint, :event_count, :window_start, :window_end,
                  :evidence_json, 'open', :created_at, :updated_at
                )
                """,
                {
                    "id": signal_id,
                    "application_id": application_id,
                    "service_id": service_id,
                    "log_source_id": log_source_id,
                    "clerk_user_id": uid,
                    "signal_type": signal_type,
                    "severity": severity,
                    "fingerprint": fingerprint,
                    "event_count": max(1, len(evidence)),
                    "window_start": window_start or now,
                    "window_end": window_end or now,
                    "evidence_json": json.dumps(evidence[-12:]),
                    "created_at": now,
                    "updated_at": now,
                },
            )
        row = self._query_one("SELECT * FROM live_signals WHERE id=:id", {"id": signal_id}) or {}
        return {
            "id": row.get("id", signal_id),
            "application_id": row.get("application_id", application_id),
            "service_id": row.get("service_id", service_id),
            "log_source_id": row.get("log_source_id"),
            "signal_type": row.get("signal_type", signal_type),
            "severity": row.get("severity", severity),
            "fingerprint": row.get("fingerprint", fingerprint),
            "event_count": int(row.get("event_count") or 0),
            "status": row.get("status", "open"),
            "updated_at": row.get("updated_at"),
        }

    def list_live_signals(self, application_id: str, clerk_user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._query(
            """
            SELECT sig.*,
                   svc.name AS service_name,
                   svc.service_type AS service_type,
                   svc.criticality AS service_criticality,
                   svc.owner AS service_owner,
                   svc.dependency_order AS dependency_order
            FROM live_signals sig
            JOIN live_services svc ON svc.id = sig.service_id
            WHERE sig.application_id=:application_id AND sig.clerk_user_id=:clerk_user_id
            ORDER BY sig.updated_at DESC
            LIMIT :limit
            """,
            {
                "application_id": application_id,
                "clerk_user_id": clerk_user_id or "anonymous",
                "limit": limit,
            },
        )
        out: list[dict[str, Any]] = []
        for row in rows:
            evidence = []
            try:
                parsed = json.loads(row.get("evidence_json") or "[]")
                if isinstance(parsed, list):
                    evidence = parsed
            except json.JSONDecodeError:
                evidence = []
            out.append(
                {
                    "id": row["id"],
                    "application_id": row["application_id"],
                    "service_id": row["service_id"],
                    "service_name": row.get("service_name"),
                    "service_type": row.get("service_type"),
                    "service_criticality": row.get("service_criticality"),
                    "service_owner": row.get("service_owner"),
                    "dependency_order": int(row.get("dependency_order") or 0),
                    "log_source_id": row.get("log_source_id"),
                    "signal_type": row.get("signal_type"),
                    "severity": row.get("severity"),
                    "fingerprint": row.get("fingerprint"),
                    "event_count": int(row.get("event_count") or 0),
                    "window_start": row.get("window_start"),
                    "window_end": row.get("window_end"),
                    "evidence": evidence,
                    "status": row.get("status"),
                    "updated_at": row.get("updated_at"),
                }
            )
        return out

    def touch_live_monitor_poll(self, clerk_user_id: str, *, polled_at: str | None = None) -> None:
        uid = clerk_user_id or "anonymous"
        stamp = polled_at or self._now_iso()
        self._ensure_user(uid)
        self._execute(
            """
            INSERT INTO live_monitor_configs (
              id, clerk_user_id, last_polled_at, created_at, updated_at
            )
            VALUES (
              :id, :clerk_user_id, :last_polled_at, :created_at, :updated_at
            )
            ON CONFLICT (clerk_user_id)
            DO UPDATE
              SET last_polled_at = EXCLUDED.last_polled_at,
                  updated_at = EXCLUDED.updated_at
            """,
            {
                "id": str(uuid.uuid4()),
                "clerk_user_id": uid,
                "last_polled_at": stamp,
                "created_at": stamp,
                "updated_at": stamp,
            },
        )

    def get_live_incident(self, live_incident_id: str, clerk_user_id: str) -> dict[str, Any] | None:
        return self._query_one(
            "SELECT * FROM live_incidents WHERE id=:id AND clerk_user_id=:clerk_user_id",
            {"id": live_incident_id, "clerk_user_id": clerk_user_id or "anonymous"},
        )

    def get_live_incident_by_fingerprint(self, clerk_user_id: str, fingerprint: str) -> dict[str, Any] | None:
        return self._query_one(
            """
            SELECT * FROM live_incidents
            WHERE clerk_user_id=:clerk_user_id AND fingerprint=:fingerprint
            """,
            {
                "clerk_user_id": clerk_user_id or "anonymous",
                "fingerprint": fingerprint,
            },
        )

    def create_live_incident(
        self,
        clerk_user_id: str,
        *,
        fingerprint: str,
        title: str,
        severity: str,
        source_log_groups: list[str],
        evidence: list[dict[str, Any]],
        event_count: int,
        incident_id: str | None = None,
        latest_job_id: str | None = None,
        first_seen_at: str | None = None,
        last_seen_at: str | None = None,
        last_analysis_at: str | None = None,
    ) -> str:
        uid = clerk_user_id or "anonymous"
        now = self._now_iso()
        first_seen = first_seen_at or now
        last_seen = last_seen_at or now
        live_incident_id = str(uuid.uuid4())
        self._ensure_user(uid)
        self._execute(
            """
            INSERT INTO live_incidents (
              id, clerk_user_id, fingerprint, title, status, severity,
              source_log_groups_json, evidence_json, event_count, incident_id,
              latest_job_id, first_seen_at, last_seen_at, last_analysis_at,
              created_at, updated_at
            )
            VALUES (
              :id, :clerk_user_id, :fingerprint, :title, 'open', :severity,
              :source_log_groups_json, :evidence_json, :event_count, :incident_id,
              :latest_job_id, :first_seen_at, :last_seen_at, :last_analysis_at,
              :created_at, :updated_at
            )
            """,
            {
                "id": live_incident_id,
                "clerk_user_id": uid,
                "fingerprint": fingerprint,
                "title": title,
                "severity": severity,
                "source_log_groups_json": json.dumps(source_log_groups),
                "evidence_json": json.dumps(evidence),
                "event_count": event_count,
                "incident_id": incident_id,
                "latest_job_id": latest_job_id,
                "first_seen_at": first_seen,
                "last_seen_at": last_seen,
                "last_analysis_at": last_analysis_at,
                "created_at": now,
                "updated_at": now,
            },
        )
        return live_incident_id

    def update_live_incident(
        self,
        live_incident_id: str,
        *,
        title: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        source_log_groups: list[str] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        event_count: int | None = None,
        incident_id: str | None = None,
        latest_job_id: str | None = None,
        last_seen_at: str | None = None,
        last_analysis_at: str | None = None,
    ) -> None:
        current = self._query_one("SELECT * FROM live_incidents WHERE id=:id", {"id": live_incident_id}) or {}
        self._execute(
            """
            UPDATE live_incidents
            SET title=:title,
                status=:status,
                severity=:severity,
                source_log_groups_json=:source_log_groups_json,
                evidence_json=:evidence_json,
                event_count=:event_count,
                incident_id=:incident_id,
                latest_job_id=:latest_job_id,
                last_seen_at=:last_seen_at,
                last_analysis_at=:last_analysis_at,
                updated_at=:updated_at
            WHERE id=:id
            """,
            {
                "id": live_incident_id,
                "title": title or current.get("title"),
                "status": status or current.get("status") or "open",
                "severity": severity or current.get("severity") or "medium",
                "source_log_groups_json": json.dumps(
                    source_log_groups
                    if source_log_groups is not None
                    else json.loads(current.get("source_log_groups_json") or "[]")
                ),
                "evidence_json": json.dumps(
                    evidence if evidence is not None else json.loads(current.get("evidence_json") or "[]")
                ),
                "event_count": event_count if event_count is not None else int(current.get("event_count") or 0),
                "incident_id": incident_id if incident_id is not None else current.get("incident_id"),
                "latest_job_id": latest_job_id if latest_job_id is not None else current.get("latest_job_id"),
                "last_seen_at": last_seen_at or current.get("last_seen_at") or self._now_iso(),
                "last_analysis_at": last_analysis_at if last_analysis_at is not None else current.get("last_analysis_at"),
                "updated_at": self._now_iso(),
            },
        )

    def list_live_incidents(self, clerk_user_id: str, limit: int = 25) -> list[dict[str, Any]]:
        return self._query(
            """
            SELECT * FROM live_incidents
            WHERE clerk_user_id=:clerk_user_id
            ORDER BY last_seen_at DESC
            LIMIT :limit
            """,
            {"clerk_user_id": clerk_user_id or "anonymous", "limit": limit},
        )

    def update_incident_assign(
        self,
        incident_id: str,
        assigned_to: str | None,
        clerk_user_id: str | None = None,
    ) -> bool:
        if clerk_user_id:
            updated = self._execute(
                """
                UPDATE incidents
                SET assigned_to=:assigned_to
                WHERE id=:incident_id AND clerk_user_id=:clerk_user_id
                """,
                {
                    "assigned_to": assigned_to,
                    "incident_id": incident_id,
                    "clerk_user_id": clerk_user_id,
                },
            )
        else:
            updated = self._execute(
                "UPDATE incidents SET assigned_to=:assigned_to WHERE id=:incident_id",
                {"assigned_to": assigned_to, "incident_id": incident_id},
            )
        return updated > 0

    def seed_remediation_actions(
        self,
        job_id: str,
        actions: list[str],
        action_type: str = "recommended",
        severity: str = "medium",
        confidence: str = "medium",
        evidence: list[str] | None = None,
        rationale: str | None = None,
        risk_if_wrong: str | None = None,
        engineer_submission: str | None = None,
        source_anchor_action_id: str | None = None,
    ) -> None:
        now = self._now_iso()
        for text in actions:
            params = {
                "id": str(uuid.uuid4()),
                "job_id": job_id,
                "action_text": text,
                "action_type": action_type,
                "severity": severity,
                "confidence": confidence,
                "evidence_json": json.dumps(evidence or []),
                "rationale": rationale,
                "risk_if_wrong": risk_if_wrong,
                "created_at": now,
                "engineer_submission": engineer_submission,
                "source_anchor_action_id": source_anchor_action_id,
            }
            try:
                self._execute(
                    """
                    INSERT INTO remediation_actions (
                      id, job_id, action_text, action_type, status,
                      severity, confidence, evidence_json, rationale, risk_if_wrong,
                      created_at, engineer_submission, source_anchor_action_id
                    )
                    VALUES (
                      :id, :job_id, :action_text, :action_type, 'pending',
                      :severity, :confidence, :evidence_json, :rationale, :risk_if_wrong,
                      :created_at, :engineer_submission, :source_anchor_action_id
                    )
                    """,
                    params,
                )
            except Exception:
                # Older Aurora schemas may not have metadata columns yet. Keep the
                # operator checklist visible while migrations catch up.
                self._execute(
                    """
                    INSERT INTO remediation_actions (
                      id, job_id, action_text, action_type, status, severity, created_at
                    )
                    VALUES (
                      :id, :job_id, :action_text, :action_type, 'pending', :severity, :created_at
                    )
                    """,
                    params,
                )

    def list_remediation_actions(self, job_id: str) -> list[dict]:
        rows = self._query(
            """
            SELECT * FROM remediation_actions
            WHERE job_id=:job_id
            ORDER BY created_at
            """,
            {"job_id": job_id},
        )
        out: list[dict] = []
        for row in rows:
            item = dict(row)
            raw = item.pop("evidence_json", "[]")
            try:
                parsed = json.loads(raw) if raw else []
                item["evidence"] = (
                    [str(x) for x in parsed if isinstance(x, str)]
                    if isinstance(parsed, list)
                    else []
                )
            except json.JSONDecodeError:
                item["evidence"] = []
            item["confidence"] = str(item.get("confidence") or "medium").lower()
            out.append(item)
        return out

    def update_remediation_action(
        self,
        action_id: str,
        status: str | None = None,
        assigned_to: str | None = None,
        notes: str | None = None,
        severity: str | None = None,
        due_date: str | None = None,
    ) -> bool:
        updates: list[str] = []
        params: dict[str, Any] = {"action_id": action_id}

        def _set(field: str, value: Any) -> None:
            key = f"p_{field}"
            updates.append(f"{field}=:{key}")
            params[key] = value

        if status is not None:
            _set("status", status)
            if status == "done":
                _set("completed_at", self._now_iso())
        if assigned_to is not None:
            _set("assigned_to", assigned_to)
        if notes is not None:
            _set("notes", notes)
        if severity is not None:
            _set("severity", severity)
        if due_date is not None:
            _set("due_date", due_date)

        if not updates:
            return False

        updated = self._execute(
            f"UPDATE remediation_actions SET {', '.join(updates)} WHERE id=:action_id",
            params,
        )
        return updated > 0

    def create_integration(
        self, clerk_user_id: str, int_type: str, config: dict, enabled: bool = True
    ) -> str:
        int_id = str(uuid.uuid4())
        uid = clerk_user_id or "anonymous"
        self._ensure_user(uid)
        self._execute(
            """
            INSERT INTO integrations (
              id, clerk_user_id, type, config_json, enabled, created_at
            )
            VALUES (
              :id, :clerk_user_id, :type, :config_json, :enabled, :created_at
            )
            """,
            {
                "id": int_id,
                "clerk_user_id": uid,
                "type": int_type,
                "config_json": json.dumps(config),
                "enabled": enabled,
                "created_at": self._now_iso(),
            },
        )
        return int_id

    @staticmethod
    def _coerce_integration_enabled(val: Any) -> bool:
        """Normalize enabled flag from SQLite/Aurora scalar types into a bool."""
        if val is None:
            return True
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return int(val) != 0
        if isinstance(val, (bytes, bytearray)):
            try:
                val = val.decode().strip()
            except UnicodeDecodeError:
                return True
        text = str(val).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off", ""):
            return False
        return True

    def list_integrations(self, clerk_user_id: str) -> list[dict]:
        rows = self._query(
            """
            SELECT * FROM integrations
            WHERE clerk_user_id=:clerk_user_id
            ORDER BY created_at DESC
            """,
            {"clerk_user_id": clerk_user_id},
        )
        out: list[dict] = []
        for row in rows:
            item = dict(row)
            try:
                item["config"] = json.loads(item.pop("config_json", "{}") or "{}")
            except json.JSONDecodeError:
                item["config"] = {}
            item["enabled"] = self._coerce_integration_enabled(item.get("enabled"))
            out.append(item)
        return out

    def delete_integration(self, integration_id: str, clerk_user_id: str) -> bool:
        updated = self._execute(
            """
            DELETE FROM integrations
            WHERE id=:integration_id AND clerk_user_id=:clerk_user_id
            """,
            {"integration_id": integration_id, "clerk_user_id": clerk_user_id},
        )
        return updated > 0

    def save_clarification_answers(self, job_id: str, answers: dict) -> None:
        self._execute(
            """
            UPDATE jobs
            SET clarification_answers_json=:answers
            WHERE id=:job_id
            """,
            {"answers": json.dumps(answers), "job_id": job_id},
        )

    def get_clarification_answers(self, job_id: str) -> dict | None:
        row = self._query_one(
            "SELECT clarification_answers_json FROM jobs WHERE id=:job_id",
            {"job_id": job_id},
        )
        raw = (row or {}).get("clarification_answers_json")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def delete_remediation_actions(self, job_id: str) -> None:
        self._execute(
            "DELETE FROM remediation_actions WHERE job_id=:job_id", {"job_id": job_id}
        )

    def update_analysis_remediation(self, job_id: str, remediation_json: str) -> None:
        row = self._query_one(
            "SELECT analysis_json FROM jobs WHERE id=:job_id", {"job_id": job_id}
        )
        raw = (row or {}).get("analysis_json")
        if not raw:
            return
        try:
            analysis = json.loads(raw)
            analysis["remediation"] = json.loads(remediation_json)
        except json.JSONDecodeError:
            return
        self._execute(
            "UPDATE jobs SET analysis_json=:analysis_json WHERE id=:job_id",
            {"job_id": job_id, "analysis_json": json.dumps(analysis)},
        )

    def create_follow_up(
        self,
        job_id: str,
        clerk_user_id: str,
        user_email: str,
        remind_at: str,
        action_id: str | None = None,
        user_name: str | None = None,
        message: str | None = None,
    ) -> str:
        follow_up_id = str(uuid.uuid4())
        uid = clerk_user_id or "anonymous"
        self._ensure_user(uid, email=user_email)
        self._execute(
            """
            INSERT INTO follow_ups (
              id, job_id, action_id, clerk_user_id, user_email,
              user_name, message, remind_at, created_at
            )
            VALUES (
              :id, :job_id, :action_id, :clerk_user_id, :user_email,
              :user_name, :message, :remind_at, :created_at
            )
            """,
            {
                "id": follow_up_id,
                "job_id": job_id,
                "action_id": action_id,
                "clerk_user_id": uid,
                "user_email": user_email,
                "user_name": user_name,
                "message": message,
                "remind_at": remind_at,
                "created_at": self._now_iso(),
            },
        )
        return follow_up_id

    def list_follow_ups(self, job_id: str) -> list[dict]:
        return self._query(
            "SELECT * FROM follow_ups WHERE job_id=:job_id ORDER BY remind_at",
            {"job_id": job_id},
        )

    def delete_follow_up(self, follow_up_id: str, clerk_user_id: str) -> bool:
        updated = self._execute(
            """
            DELETE FROM follow_ups
            WHERE id=:follow_up_id AND clerk_user_id=:clerk_user_id
            """,
            {"follow_up_id": follow_up_id, "clerk_user_id": clerk_user_id},
        )
        return updated > 0

    def get_pending_follow_ups(self, before_iso: str) -> list[dict]:
        return self._query(
            """
            SELECT * FROM follow_ups
            WHERE sent_at IS NULL AND remind_at <= :before_iso
            ORDER BY remind_at
            """,
            {"before_iso": before_iso},
        )

    def mark_follow_up_sent(self, follow_up_id: str) -> None:
        self._execute(
            "UPDATE follow_ups SET sent_at=:sent_at WHERE id=:follow_up_id",
            {"sent_at": self._now_iso(), "follow_up_id": follow_up_id},
        )

    def save_chat_message(
        self, job_id: str, action_id: str, role: str, content: str
    ) -> str:
        msg_id = str(uuid.uuid4())
        self._execute(
            """
            INSERT INTO chat_messages (id, job_id, action_id, role, content, created_at)
            VALUES (:id, :job_id, :action_id, :role, :content, :created_at)
            """,
            {
                "id": msg_id,
                "job_id": job_id,
                "action_id": action_id,
                "role": role,
                "content": content,
                "created_at": self._now_iso(),
            },
        )
        return msg_id

    def list_chat_messages(self, job_id: str, action_id: str) -> list[dict]:
        return self._query(
            """
            SELECT * FROM chat_messages
            WHERE job_id=:job_id AND action_id=:action_id
            ORDER BY created_at
            """,
            {"job_id": job_id, "action_id": action_id},
        )

    def list_chat_messages_for_job(self, job_id: str) -> list[dict]:
        return self._query(
            """
            SELECT * FROM chat_messages
            WHERE job_id=:job_id
            ORDER BY action_id, created_at
            """,
            {"job_id": job_id},
        )

    def seed_trail_action(
        self,
        job_id: str,
        action_text: str,
        severity: str,
        action_type: str,
        parent_action_id: str,
        confidence: str = "medium",
        evidence: list[str] | None = None,
        rationale: str | None = None,
        risk_if_wrong: str | None = None,
    ) -> str:
        action_id = str(uuid.uuid4())
        self._execute(
            """
            INSERT INTO remediation_actions (
              id, job_id, action_text, action_type, status,
              severity, confidence, evidence_json, rationale, risk_if_wrong,
              parent_action_id, created_at
            )
            VALUES (
              :id, :job_id, :action_text, :action_type, 'pending',
              :severity, :confidence, :evidence_json, :rationale, :risk_if_wrong,
              :parent_action_id, :created_at
            )
            """,
            {
                "id": action_id,
                "job_id": job_id,
                "action_text": action_text,
                "action_type": action_type,
                "severity": severity,
                "confidence": confidence,
                "evidence_json": json.dumps(evidence or []),
                "rationale": rationale,
                "risk_if_wrong": risk_if_wrong,
                "parent_action_id": parent_action_id,
                "created_at": self._now_iso(),
            },
        )
        return action_id

    def save_action_eval_response(self, action_id: str, response: str) -> None:
        self._execute(
            """
            UPDATE remediation_actions
            SET eval_response=:eval_response
            WHERE id=:action_id
            """,
            {"eval_response": response, "action_id": action_id},
        )

    def get_action(self, action_id: str) -> dict | None:
        return self._query_one(
            "SELECT * FROM remediation_actions WHERE id=:action_id",
            {"action_id": action_id},
        )

    def save_pir(self, job_id: str, pir_json: str) -> None:
        self._execute(
            "UPDATE jobs SET pir_json=:pir_json WHERE id=:job_id",
            {"pir_json": pir_json, "job_id": job_id},
        )

    def get_pir(self, job_id: str) -> dict | None:
        row = self._query_one(
            "SELECT pir_json FROM jobs WHERE id=:job_id", {"job_id": job_id}
        )
        raw = (row or {}).get("pir_json")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def update_incident_resolution(
        self,
        incident_id: str,
        status: str,
        resolution_notes: str | None,
        clerk_user_id: str | None = None,
    ) -> bool:
        resolved_at = self._now_iso() if status == "resolved" else None
        if clerk_user_id:
            updated = self._execute(
                """
                UPDATE incidents
                SET status=:status,
                    resolution_notes=:resolution_notes,
                    resolved_at=COALESCE(:resolved_at, resolved_at)
                WHERE id=:incident_id AND clerk_user_id=:clerk_user_id
                """,
                {
                    "status": status,
                    "resolution_notes": resolution_notes,
                    "resolved_at": resolved_at,
                    "incident_id": incident_id,
                    "clerk_user_id": clerk_user_id,
                },
            )
        else:
            updated = self._execute(
                """
                UPDATE incidents
                SET status=:status,
                    resolution_notes=:resolution_notes,
                    resolved_at=COALESCE(:resolved_at, resolved_at)
                WHERE id=:incident_id
                """,
                {
                    "status": status,
                    "resolution_notes": resolution_notes,
                    "resolved_at": resolved_at,
                    "incident_id": incident_id,
                },
            )
        return updated > 0


# ---------------------------------------------------------------------------
# SQLite backend  (local development)
# ---------------------------------------------------------------------------


class SqliteDatabase(_SentinelDb):
    """SQLite-backed store for local development. Zero AWS credentials required."""

    def __init__(self, path: str | None = None) -> None:
        self._path = path or sqlite_path()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._bootstrap()

    # Columns that may be absent from databases created before they were added.
    # Each entry is (table, column, sqlite_type_and_default).
    _MIGRATIONS: list[tuple[str, str, str]] = [
        ("jobs", "pipeline_events", "TEXT NOT NULL DEFAULT '[]'"),
        ("jobs", "similar_incidents_json", "TEXT"),
        ("jobs", "clarification_answers_json", "TEXT"),
        ("jobs", "pir_json", "TEXT"),
        ("jobs", "current_stage", "TEXT"),
        ("jobs", "completed_at", "TEXT"),
        ("jobs", "error_message", "TEXT"),
        ("incidents", "sanitized_text", "TEXT"),
        ("incidents", "guardrail_json", "TEXT"),
        ("incidents", "assigned_to", "TEXT"),
        ("incidents", "resolved_at", "TEXT"),
        ("incidents", "resolution_notes", "TEXT"),
        ("remediation_actions", "parent_action_id", "TEXT"),
        ("remediation_actions", "eval_response", "TEXT"),
        ("remediation_actions", "engineer_submission", "TEXT"),
        ("remediation_actions", "source_anchor_action_id", "TEXT"),
        ("remediation_actions", "due_date", "TEXT"),
        ("remediation_actions", "confidence", "TEXT NOT NULL DEFAULT 'medium'"),
        ("remediation_actions", "evidence_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("remediation_actions", "rationale", "TEXT"),
        ("remediation_actions", "risk_if_wrong", "TEXT"),
        ("remediation_actions", "notes", "TEXT"),
        ("remediation_actions", "assigned_to", "TEXT"),
        ("remediation_actions", "completed_at", "TEXT"),
        ("follow_ups", "action_id", "TEXT"),
        ("follow_ups", "user_name", "TEXT"),
        ("follow_ups", "message", "TEXT"),
        ("follow_ups", "sent_at", "TEXT"),
    ]

    def _bootstrap(self) -> None:
        """Create tables/indexes and apply any missing-column migrations."""
        with self._lock:
            statements = [s.strip() for s in _SCHEMA_SQL.split(";") if s.strip()]
            with self._conn:
                for stmt in statements:
                    self._conn.execute(stmt)
                # Add columns that may be missing from pre-existing databases.
                for table, column, definition in self._MIGRATIONS:
                    try:
                        self._conn.execute(
                            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                        )
                    except sqlite3.OperationalError:
                        pass  # column already exists

    def _query(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, params or {})
            return [dict(row) for row in cur.fetchall()]

    def _query_one(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> dict[str, Any] | None:
        rows = self._query(sql, params)
        return rows[0] if rows else None

    def _execute(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> int:
        with self._lock:
            with self._conn:
                cur = self._conn.execute(sql, params or {})
            return cur.rowcount

    def execute_script(self, statements: list[str]) -> None:
        with self._lock:
            with self._conn:
                for stmt in statements:
                    sql = stmt.strip()
                    if sql:
                        self._conn.execute(sql)

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Aurora Data API backend  (production / AWS Lambda)
# ---------------------------------------------------------------------------


class Database(_SentinelDb):
    """Aurora Serverless Data API backend."""

    def __init__(self, database_name: str | None = None) -> None:
        self.cluster_arn = aurora_cluster_arn()
        self.secret_arn = aurora_secret_arn()
        self.database = (database_name or aurora_database()).strip() or "sentinel"
        self.region = aurora_region()

        if not self.cluster_arn or not self.secret_arn:
            raise ValueError(
                "Aurora not configured. Set AURORA_CLUSTER_ARN and AURORA_SECRET_ARN."
            )

        self._client = boto3.client("rds-data", region_name=self.region)

    @staticmethod
    def _encode_param(value: Any) -> dict[str, Any]:
        if value is None:
            return {"isNull": True}
        if isinstance(value, bool):
            return {"booleanValue": value}
        if isinstance(value, int):
            return {"longValue": value}
        if isinstance(value, float):
            return {"doubleValue": value}
        return {"stringValue": str(value)}

    @classmethod
    def _build_params(cls, params: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not params:
            return []
        return [{"name": k, "value": cls._encode_param(v)} for k, v in params.items()]

    @staticmethod
    def _decode_field(field: dict[str, Any]) -> Any:
        if field.get("isNull"):
            return None
        if "stringValue" in field:
            return field["stringValue"]
        if "longValue" in field:
            return field["longValue"]
        if "doubleValue" in field:
            return field["doubleValue"]
        if "booleanValue" in field:
            return field["booleanValue"]
        if "arrayValue" in field:
            return [
                Database._decode_field(i)
                for i in field["arrayValue"].get("arrayValues", [])
            ]
        if "blobValue" in field:
            return field["blobValue"]
        return None

    def _run_statement(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        include_metadata: bool = False,
        transaction_id: str | None = None,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "resourceArn": self.cluster_arn,
            "secretArn": self.secret_arn,
            "database": self.database,
            "sql": sql,
            "parameters": self._build_params(params),
            "includeResultMetadata": include_metadata,
        }
        if transaction_id:
            request["transactionId"] = transaction_id
        return self._client.execute_statement(**request)

    def _query(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]:
        response = self._run_statement(
            sql, params, include_metadata=True, transaction_id=transaction_id
        )
        metadata = response.get("columnMetadata") or []
        if not metadata:
            return []
        columns = [(c.get("label") or c.get("name") or "").strip() for c in metadata]
        rows: list[dict[str, Any]] = []
        for rec in response.get("records") or []:
            row: dict[str, Any] = {}
            for idx, field in enumerate(rec):
                key = columns[idx] if idx < len(columns) else f"col_{idx}"
                row[key] = self._decode_field(field)
            rows.append(row)
        return rows

    def _query_one(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> dict[str, Any] | None:
        rows = self._query(sql, params, transaction_id=transaction_id)
        return rows[0] if rows else None

    def _execute(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> int:
        response = self._run_statement(sql, params, transaction_id=transaction_id)
        return int(response.get("numberOfRecordsUpdated") or 0)

    def execute_script(self, statements: list[str]) -> None:
        if not statements:
            return
        tx = self._client.begin_transaction(
            resourceArn=self.cluster_arn,
            secretArn=self.secret_arn,
            database=self.database,
        )["transactionId"]
        try:
            for statement in statements:
                sql = statement.strip()
                if sql:
                    self._execute(sql, transaction_id=tx)
            self._client.commit_transaction(
                resourceArn=self.cluster_arn,
                secretArn=self.secret_arn,
                transactionId=tx,
            )
        except Exception:
            self._client.rollback_transaction(
                resourceArn=self.cluster_arn,
                secretArn=self.secret_arn,
                transactionId=tx,
            )
            raise

    def close(self) -> None:
        """No persistent connection to close for Data API client."""


# ---------------------------------------------------------------------------
# PostgreSQL backend (GCP Cloud SQL / direct Postgres)
# ---------------------------------------------------------------------------


class PostgresDatabase(_SentinelDb):
    """PostgreSQL backend for GCP Cloud SQL.

    Cloud Run connects through the Cloud SQL Unix socket at
    ``/cloudsql/{connection_name}``. Local smoke tests can use ``DATABASE_URL``
    or ``GCP_DB_HOST`` / ``GCP_DB_PORT``.
    """

    _PARAM_RE = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_]*)")

    def __init__(self) -> None:
        self._connector = None
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - environment/setup issue
            raise RuntimeError(
                "psycopg is required for the GCP Cloud SQL/Postgres backend."
            ) from exc

        self._psycopg = psycopg
        database_url = os.getenv("DATABASE_URL", "").strip()
        connection_name = gcp_cloudsql_connection_name()
        use_connector = (
            connection_name
            and os.getenv("GCP_USE_CLOUDSQL_CONNECTOR", "true").lower() == "true"
            and not database_url
        )
        self._driver = "psycopg"
        if use_connector:
            try:
                from google.cloud.sql.connector import Connector

                self._connector = Connector(refresh_strategy="LAZY")
                self._conn = self._connector.connect(
                    connection_name,
                    "pg8000",
                    user=gcp_db_user(),
                    password=gcp_db_password(),
                    db=gcp_db_name(),
                    ip_type=os.getenv("GCP_CLOUDSQL_IP_TYPE", "public"),
                )
                self._driver = "pg8000"
            except ImportError as exc:  # pragma: no cover - environment/setup issue
                raise RuntimeError(
                    "cloud-sql-python-connector[pg8000] is required for Cloud SQL connector mode."
                ) from exc
        elif database_url:
            kwargs: dict[str, Any] = {"row_factory": dict_row}
            self._conn = psycopg.connect(database_url, **kwargs)
        else:
            kwargs = {"row_factory": dict_row}
            host = f"/cloudsql/{connection_name}" if connection_name else gcp_db_host()
            self._conn = psycopg.connect(
                dbname=gcp_db_name(),
                user=gcp_db_user(),
                password=gcp_db_password(),
                host=host,
                port=gcp_db_port(),
                **kwargs,
            )
        self._lock = threading.Lock()

    @classmethod
    def _sql(cls, sql: str) -> str:
        return cls._PARAM_RE.sub(r"%(\1)s", sql)

    @classmethod
    def _pg8000_sql(
        cls, sql: str, params: dict[str, Any] | None
    ) -> tuple[str, list[Any]]:
        values: list[Any] = []

        def repl(match: re.Match[str]) -> str:
            key = match.group(1)
            values.append((params or {}).get(key))
            return "%s"

        return cls._PARAM_RE.sub(repl, sql), values

    def _query(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]:
        del transaction_id
        with self._lock:
            if self._driver == "pg8000":
                cur = self._conn.cursor()
                try:
                    q, values = self._pg8000_sql(sql, params)
                    cur.execute(q, values)
                    columns = [col[0] for col in cur.description or []]
                    return [dict(zip(columns, row)) for row in cur.fetchall()]
                finally:
                    cur.close()
            with self._conn.cursor() as cur:
                cur.execute(self._sql(sql), params or {})
                return [dict(row) for row in cur.fetchall()]

    def _query_one(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> dict[str, Any] | None:
        del transaction_id
        with self._lock:
            if self._driver == "pg8000":
                cur = self._conn.cursor()
                try:
                    q, values = self._pg8000_sql(sql, params)
                    cur.execute(q, values)
                    row = cur.fetchone()
                    if not row:
                        return None
                    columns = [col[0] for col in cur.description or []]
                    return dict(zip(columns, row))
                finally:
                    cur.close()
            with self._conn.cursor() as cur:
                cur.execute(self._sql(sql), params or {})
                row = cur.fetchone()
                return dict(row) if row else None

    def _execute(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> int:
        del transaction_id
        with self._lock:
            if self._driver == "pg8000":
                try:
                    cur = self._conn.cursor()
                    try:
                        q, values = self._pg8000_sql(sql, params)
                        cur.execute(q, values)
                        rowcount = int(cur.rowcount or 0)
                    finally:
                        cur.close()
                    self._conn.commit()
                    return rowcount
                except Exception:
                    self._conn.rollback()
                    raise
            with self._conn.transaction():
                with self._conn.cursor() as cur:
                    cur.execute(self._sql(sql), params or {})
                    return int(cur.rowcount or 0)

    def execute_script(self, statements: list[str]) -> None:
        with self._lock:
            if self._driver == "pg8000":
                try:
                    cur = self._conn.cursor()
                    try:
                        for statement in statements:
                            sql = statement.strip()
                            if sql:
                                cur.execute(sql)
                    finally:
                        cur.close()
                    self._conn.commit()
                except Exception:
                    self._conn.rollback()
                    raise
                return
            with self._conn.transaction():
                with self._conn.cursor() as cur:
                    for statement in statements:
                        sql = statement.strip()
                        if sql:
                            cur.execute(sql)

    def close(self) -> None:
        self._conn.close()
        if self._connector is not None:
            self._connector.close()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_database() -> _SentinelDb:
    """Return a SqliteDatabase locally or an Aurora Database in production."""
    if is_local():
        return SqliteDatabase()
    if gcp_postgres_configured():
        return PostgresDatabase()
    return Database()
