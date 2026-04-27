"""Database adapter tests for SQL helpers and local persistence behavior."""

from __future__ import annotations

import json
from pathlib import Path

from common.models import (
    GuardrailReport,
    IncidentAnalysis,
    IncidentSummary,
    RemediationPlan,
    RootCauseAnalysis,
)
from common.store import SqliteDatabase
from database.src.db import get_database, load_sql_statements, migration_file


def _analysis(job_id: str, incident_id: str) -> IncidentAnalysis:
    return IncidentAnalysis(
        incident_id=incident_id,
        job_id=job_id,
        summary=IncidentSummary(
            summary="Database writes failing intermittently",
            severity="medium",
            severity_reason="Partial customer impact",
        ),
        root_cause=RootCauseAnalysis(
            likely_root_cause="Deadlock retries exhausted",
            confidence="medium",
            reasoning="Error traces match lock timeout pattern",
            supporting_evidence=["lock timeout reached", "retry budget exhausted"],
        ),
        remediation=RemediationPlan(
            recommended_actions=["Reduce write contention"],
            next_checks=["Observe lock wait metrics"],
            risk_if_unresolved="Write path remains unstable",
            recommended_severities=["medium"],
            check_severities=["low"],
        ),
        guardrails=GuardrailReport(),
        models={"model": "unit-test"},
    )


def test_migration_file_points_to_existing_schema() -> None:
    path = migration_file()
    assert path.name == "001_schema.sql"
    assert path.exists()


def test_load_sql_statements_strips_comment_lines(tmp_path: Path) -> None:
    sql_file = tmp_path / "example.sql"
    sql_file.write_text(
        "-- comment to skip\nSELECT 1;\n\n-- another comment\nSELECT 2;\n",
        encoding="utf-8",
    )
    statements = load_sql_statements(sql_file)
    assert statements == ["SELECT 1", "SELECT 2"]


def test_get_database_returns_sqlite_when_aurora_not_configured(
    isolated_local_db: None,
) -> None:
    db = get_database()
    try:
        assert isinstance(db, SqliteDatabase)
    finally:
        db.close()


def test_sqlite_database_persists_incident_job_analysis_and_actions(
    isolated_local_db: None,
) -> None:
    db = get_database()
    incident_id = db.create_incident(
        text="2026-04-27T12:30:00Z ERROR queue backlog",
        title="Queue backlog",
        source="manual",
        clerk_user_id="tenant-a",
    )
    job_id = db.create_job(incident_id=incident_id, clerk_user_id="tenant-a")
    db.set_job_stage(job_id, "normalize", "Normalizing incident text")

    analysis = _analysis(job_id, incident_id)
    db.save_analysis(job_id, analysis)
    db.seed_remediation_actions(
        job_id,
        ["Drain stale queue consumers"],
        action_type="recommended",
        severity="high",
        confidence="medium",
        evidence=["queue depth exceeded 10k"],
        rationale="Reduce pressure quickly",
        risk_if_wrong="Could waste response time",
    )

    row = db.get_job_with_incident(job_id, clerk_user_id="tenant-a")
    assert row is not None
    assert row["status"] == "completed"
    assert "normalize" in (row.get("pipeline_events") or "")

    parsed = json.loads(row["analysis_json"])
    assert parsed["summary"]["severity"] == "medium"
    actions = db.list_remediation_actions(job_id)
    assert len(actions) == 1
    assert actions[0]["action_text"] == "Drain stale queue consumers"
    assert actions[0]["evidence"] == ["queue depth exceeded 10k"]
    db.close()


def test_sqlite_database_enforces_tenant_scoped_reads(
    isolated_local_db: None,
) -> None:
    db = get_database()
    incident_id = db.create_incident(
        text="2026-04-27T13:00:00Z ERROR auth provider timeout",
        title="Auth timeout",
        source="upload",
        clerk_user_id="tenant-a",
    )
    job_id = db.create_job(incident_id=incident_id, clerk_user_id="tenant-a")

    assert db.get_job(job_id, clerk_user_id="tenant-a") is not None
    assert db.get_job(job_id, clerk_user_id="tenant-b") is None
    assert db.get_incident(incident_id, clerk_user_id="tenant-b") is None
    db.close()


def test_sqlite_database_integration_payload_roundtrip(
    isolated_local_db: None,
) -> None:
    db = get_database()
    integration_id = db.create_integration(
        "tenant-a",
        "generic_webhook",
        {"webhook_url": "https://example.test/webhook", "channel": "ops"},
        enabled=True,
    )
    rows = db.list_integrations("tenant-a")
    assert len(rows) == 1
    assert rows[0]["id"] == integration_id
    assert rows[0]["config"]["channel"] == "ops"
    assert rows[0]["enabled"] is True
    db.close()
