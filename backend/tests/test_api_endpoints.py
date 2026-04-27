"""API-level tests covering auth, lifecycle, and workflow endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from common.models import (
    GuardrailReport,
    IncidentAnalysis,
    IncidentSummary,
    JobRunResponse,
    RemediationPlan,
    RootCauseAnalysis,
)
from common.store import get_database


def _analysis_for(job_id: str, incident_id: str) -> IncidentAnalysis:
    return IncidentAnalysis(
        incident_id=incident_id,
        job_id=job_id,
        summary=IncidentSummary(
            summary="Checkout service returns timeout errors",
            severity="high",
            severity_reason="Customer-facing degradation",
        ),
        root_cause=RootCauseAnalysis(
            likely_root_cause="Pool exhaustion",
            confidence="high",
            reasoning="Pool wait and timeout logs are correlated",
            supporting_evidence=["pool wait > 30s", "timeout burst on API"],
        ),
        remediation=RemediationPlan(
            recommended_actions=["Increase pool size"],
            next_checks=["Watch timeout metrics"],
            risk_if_unresolved="Customer impact persists",
            recommended_severities=["high"],
            check_severities=["medium"],
        ),
        guardrails=GuardrailReport(),
        models={"model": "unit-test"},
    )


def test_health_returns_service_metadata(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "sentinel-api"}


def test_create_incident_creates_pending_job_and_lists_in_jobs(
    isolated_local_db: None, auth_disabled: None, monkeypatch
) -> None:
    from api import main as api_main

    monkeypatch.setattr(api_main, "_background_run_job", lambda *_args: None)
    client = TestClient(api_main.app)

    created = client.post(
        "/api/incidents",
        json={
            "title": "API timeout incident",
            "source": "manual",
            "text": "2026-04-27T10:30:00Z ERROR checkout timeout while querying db",
        },
    )
    assert created.status_code == 200, created.text
    payload = created.json()
    assert payload["status"] == "pending"

    listed = client.get("/api/jobs")
    assert listed.status_code == 200, listed.text
    jobs = listed.json()
    assert any(item["job_id"] == payload["job_id"] for item in jobs)


def test_analyze_sync_uses_pipeline_result_model(
    isolated_local_db: None, auth_disabled: None, monkeypatch
) -> None:
    from api import main as api_main

    called: dict[str, str] = {}

    def _fake_run(job_id: str, db, clerk_user_id: str):  # noqa: ANN001
        called["job_id"] = job_id
        called["clerk_user_id"] = clerk_user_id
        row = db.get_job(job_id, clerk_user_id=clerk_user_id)
        assert row is not None
        return JobRunResponse(
            incident_id=row["incident_id"],
            job_id=job_id,
            status="completed",
            analysis=_analysis_for(job_id, row["incident_id"]),
        )

    monkeypatch.setattr(api_main, "run_job", _fake_run)
    client = TestClient(api_main.app)

    response = client.post(
        "/api/incidents/analyze-sync",
        json={
            "title": "Analyze sync incident",
            "source": "manual",
            "text": "2026-04-27T11:00:00Z ERROR database connection refused",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["analysis"]["summary"]["severity"] == "high"
    assert called["clerk_user_id"] == "dev_user"


def test_run_analysis_returns_404_for_unknown_job(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    client = TestClient(app)
    response = client.post("/api/jobs/missing-job/run")
    assert response.status_code == 404
    assert response.json()["detail"] == "Job not found"


def test_workflow_endpoint_returns_full_snapshot_for_completed_job(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from common.pipeline import create_incident_and_job
    from api.main import app
    from common.models import IncidentInput

    db = get_database()
    incident_id, job_id = create_incident_and_job(
        IncidentInput(
            title="Workflow snapshot incident",
            source="manual",
            text="2026-04-27T11:30:00Z ERROR worker crashed in region-eu",
        ),
        db,
        clerk_user_id="dev_user",
    )
    db.save_analysis(job_id, _analysis_for(job_id, incident_id))
    db.seed_remediation_actions(
        job_id,
        ["Roll restart checkout worker"],
        action_type="recommended",
        severity="high",
        confidence="high",
        evidence=["worker crash loop"],
        rationale="Primary path to restore service",
        risk_if_wrong="Recovery is delayed",
    )
    db.close()

    client = TestClient(app)
    response = client.get(f"/api/jobs/{job_id}/workflow")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job"]["job_id"] == job_id
    assert body["analysis"]["summary"]["severity"] == "high"
    assert len(body["remediation_actions"]) == 1
    assert "incident" in body


def test_update_incident_status_validates_and_persists_changes(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from common.pipeline import create_incident_and_job
    from api.main import app
    from common.models import IncidentInput

    db = get_database()
    incident_id, _ = create_incident_and_job(
        IncidentInput(
            title="Resolution status incident",
            source="manual",
            text="2026-04-27T12:00:00Z ERROR auth token verification failed",
        ),
        db,
        clerk_user_id="dev_user",
    )
    db.close()

    client = TestClient(app)

    bad = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={"status": "invalid-status", "resolution_notes": "note"},
    )
    # Request model rejects unsupported enum values before endpoint business logic.
    assert bad.status_code == 422

    ok = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={"status": "resolved", "resolution_notes": "incident fixed"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["updated"] is True

    verify_db = get_database()
    row = verify_db.get_incident(incident_id, clerk_user_id="dev_user")
    verify_db.close()
    assert row is not None
    assert row["status"] == "resolved"
    assert row["resolution_notes"] == "incident fixed"
