"""Detailed tests for pipeline orchestration and workflow dispatch."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from common.models import (
    GuardrailReport,
    IncidentAnalysis,
    IncidentInput,
    IncidentSummary,
    NormalizedIncident,
    RemediationPlan,
    RootCauseAnalysis,
)
from common.pipeline import _fire_integrations, create_incident_and_job, run_job
from common.store import get_database


def _valid_input() -> IncidentInput:
    return IncidentInput(
        title="Service outage",
        source="manual",
        text="2026-04-27T10:00:00Z ERROR checkout-service timeout",
    )


def _analysis(summary_severity: str = "high") -> IncidentAnalysis:
    return IncidentAnalysis(
        incident_id="inc-1",
        job_id="job-1",
        summary=IncidentSummary(
            summary="Checkout failures increased sharply",
            severity=summary_severity,  # type: ignore[arg-type]
            severity_reason="Error rate and customer impact are high",
        ),
        root_cause=RootCauseAnalysis(
            likely_root_cause="DB connection pool exhaustion",
            confidence="high",
            reasoning="Pool wait time and timeout logs align",
            supporting_evidence=["pool wait > 30s", "timeout spikes observed"],
        ),
        remediation=RemediationPlan(
            recommended_actions=["Increase DB pool size"],
            next_checks=["Verify timeout rate declines"],
            risk_if_unresolved="Revenue-impacting checkout outage may continue",
            recommended_severities=["high"],
            check_severities=["medium"],
        ),
        guardrails=GuardrailReport(),
        models={"model": "unit-test-model"},
    )


def test_run_job_completes_full_workflow_and_seeds_actions(
    isolated_local_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = get_database()
    incident_id, job_id = create_incident_and_job(
        _valid_input(), db, clerk_user_id="user-1"
    )
    assert incident_id
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "common.pipeline.normalize_incident",
        lambda _raw: NormalizedIncident(
            normalized_text="normalized incident body",
            evidence_snippets=["timeout in checkout worker", "pool wait exceeded"],
            guardrails=GuardrailReport(notes=["sanitized"]),
        ),
    )
    monkeypatch.setattr(
        "common.pipeline.summarize_incident",
        lambda _normalized: IncidentSummary(
            summary="Checkout degraded due to database pressure",
            severity="high",
            severity_reason="High error rate",
        ),
    )
    monkeypatch.setattr(
        "common.pipeline.investigate_root_cause",
        lambda _normalized, _summary: RootCauseAnalysis(
            likely_root_cause="Connection pool exhaustion",
            confidence="high",
            reasoning="Worker logs and pool metrics correlate",
            supporting_evidence=["pool wait exceeded", "connection timeout"],
        ),
    )
    monkeypatch.setattr(
        "common.pipeline.generate_remediation",
        lambda _normalized, _summary, _rc: RemediationPlan(
            recommended_actions=["Increase DB pool limits"],
            next_checks=["Confirm error rate stabilizes"],
            risk_if_unresolved="Service remains unavailable",
            recommended_severities=["critical"],
            check_severities=["not-a-valid-severity"],
        ),
    )
    monkeypatch.setattr(
        "common.pipeline._fire_integrations",
        lambda *args, **kwargs: captured.update({"args": args, "kwargs": kwargs}),
    )

    result = run_job(job_id, db, clerk_user_id="user-1")
    assert result.status == "completed"
    assert result.analysis is not None
    assert result.analysis.summary.severity == "high"

    actions = db.list_remediation_actions(job_id)
    assert len(actions) == 2
    assert actions[0]["action_type"] == "recommended"
    assert actions[0]["severity"] == "critical"
    assert actions[0]["confidence"] in {"medium", "high"}
    assert actions[1]["action_type"] == "check"
    assert actions[1]["severity"] == "medium"  # fallback from high incident severity

    row = db.get_job(job_id, clerk_user_id="user-1")
    assert row is not None
    assert row["status"] == "completed"
    assert row["current_stage"] == "completed"
    assert "queued" in (row.get("pipeline_events") or "")
    assert "root_cause" in (row.get("pipeline_events") or "")

    assert "args" in captured
    assert captured["args"][0] == job_id
    db.close()


def test_run_job_returns_processing_when_job_already_processing(
    isolated_local_db: None,
) -> None:
    db = get_database()
    _, job_id = create_incident_and_job(_valid_input(), db, clerk_user_id="user-1")
    db.update_job_status(job_id, "processing")

    result = run_job(job_id, db, clerk_user_id="user-1")
    assert result.status == "processing"
    assert result.analysis is None
    db.close()


def test_run_job_reuses_existing_completed_analysis_without_rerun(
    isolated_local_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = get_database()
    incident_id, job_id = create_incident_and_job(
        _valid_input(), db, clerk_user_id="user-1"
    )
    analysis = _analysis(summary_severity="critical")
    analysis.incident_id = incident_id
    analysis.job_id = job_id
    db.save_analysis(job_id, analysis)

    def _should_not_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("normalize_incident should not run for completed jobs")

    monkeypatch.setattr("common.pipeline.normalize_incident", _should_not_run)

    result = run_job(job_id, db, clerk_user_id="user-1")
    assert result.status == "completed"
    assert result.analysis is not None
    assert result.analysis.summary.severity == "critical"
    db.close()


def test_run_job_marks_failed_when_stage_raises(
    isolated_local_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = get_database()
    _, job_id = create_incident_and_job(_valid_input(), db, clerk_user_id="user-1")
    monkeypatch.setattr(
        "common.pipeline.normalize_incident",
        lambda _raw: (_ for _ in ()).throw(RuntimeError("normalization failed")),
    )

    result = run_job(job_id, db, clerk_user_id="user-1")
    assert result.status == "failed"
    assert "normalization failed" in (result.error or "")

    row = db.get_job(job_id, clerk_user_id="user-1")
    assert row is not None
    assert row["status"] == "failed"
    assert row["current_stage"] == "failed"
    db.close()


def test_fire_integrations_merges_user_integrations_and_dispatches_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INTEGRATION_NOTIFY_SEVERITIES", "high,critical")

    class _FakeDb:
        def list_integrations(self, uid: str) -> list[dict]:
            if uid == "owner":
                return [
                    {"id": "a", "enabled": True, "type": "slack", "config": {}},
                    {"id": "dup", "enabled": True, "type": "slack", "config": {}},
                ]
            return [
                {"id": "dup", "enabled": True, "type": "slack", "config": {}},
                {"id": "b", "enabled": True, "type": "generic_webhook", "config": {}},
            ]

    with patch("integrations.dispatcher.dispatch_all") as dispatch_all:
        _fire_integrations(
            "job-1",
            _analysis(summary_severity="high"),
            _FakeDb(),
            "owner",
            incident_title="checkout-log.txt",
            incident_source="upload",
            alternate_user_id="api-caller",
        )
        dispatch_all.assert_called_once()
        integrations = dispatch_all.call_args.args[0]
        assert len(integrations) == 3  # dedupe duplicate id from alternate owner


def test_fire_integrations_skips_when_severity_not_in_notify_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INTEGRATION_NOTIFY_SEVERITIES", "critical")

    class _FakeDb:
        def list_integrations(self, _uid: str) -> list[dict]:
            return [{"id": "x", "enabled": True, "type": "slack", "config": {}}]

    with patch("integrations.dispatcher.dispatch_all") as dispatch_all:
        _fire_integrations(
            "job-1",
            _analysis(summary_severity="high"),
            _FakeDb(),  # type: ignore[arg-type]
            "owner",
        )
        dispatch_all.assert_not_called()
