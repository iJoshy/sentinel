"""Persistence layer for Sentinel – Aurora (production) and SQLite (local)."""

from __future__ import annotations

import json
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
                {
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
                },
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
# Factory
# ---------------------------------------------------------------------------


def get_database() -> _SentinelDb:
    """Return a SqliteDatabase locally or an Aurora Database in production."""
    if is_local():
        return SqliteDatabase()
    return Database()
