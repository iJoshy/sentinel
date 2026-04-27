"""Extended API tests for remediation, clarification, replay, and reporting workflows."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from common.models import (
    ActionEvaluationResult,
    ClarificationQuestion,
    ClarificationSet,
    GuardrailReport,
    IncidentAnalysis,
    IncidentInput,
    IncidentSummary,
    PostIncidentReview,
    RemediationFollowUp,
    RemediationPlan,
    ReplayExplainResponse,
    ReplayFrame,
    ReplayResponse,
    RootCauseAnalysis,
)
from common.pipeline import create_incident_and_job
from common.store import get_database


def _seed_completed_job(user_id: str = "dev_user") -> tuple[str, str]:
    db = get_database()
    incident_id, job_id = create_incident_and_job(
        IncidentInput(
            title="Extended workflow incident",
            source="manual",
            text="2026-04-27T13:15:00Z ERROR db timeout from checkout worker",
        ),
        db,
        clerk_user_id=user_id,
    )
    db.save_analysis(
        job_id,
        IncidentAnalysis(
            incident_id=incident_id,
            job_id=job_id,
            summary=IncidentSummary(
                summary="Checkout is degraded",
                severity="high",
                severity_reason="Error spike and customer impact",
            ),
            root_cause=RootCauseAnalysis(
                likely_root_cause="DB pool exhaustion",
                confidence="high",
                reasoning="Timeout and pool-wait logs correlate",
                supporting_evidence=["timeout spike", "pool wait exceeded"],
            ),
            remediation=RemediationPlan(
                recommended_actions=["Increase DB pool"],
                next_checks=["Watch timeout metric"],
                risk_if_unresolved="Outage can continue",
                recommended_severities=["high"],
                check_severities=["medium"],
            ),
            guardrails=GuardrailReport(),
            models={"model": "unit-test"},
        ),
    )
    db.seed_remediation_actions(
        job_id,
        ["Increase DB pool"],
        action_type="recommended",
        severity="high",
        confidence="high",
        evidence=["pool wait exceeded"],
        rationale="Primary mitigation",
        risk_if_wrong="May not reduce timeout rate",
    )
    db.close()
    return incident_id, job_id


def test_clarification_questions_returns_generated_question_set(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    client = TestClient(app)
    question_set = ClarificationSet(
        job_id=job_id,
        questions=[
            ClarificationQuestion(
                id="q1",
                question="Did errors start after a deploy?",
                rationale="Deployment timing can narrow root cause",
                kind="yes_no",
            )
        ],
        urgency="suggested",
        already_answered=False,
    )

    with patch("remediator.agent.build_clarification_set", return_value=question_set):
        response = client.get(f"/api/jobs/{job_id}/clarification-questions")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["job_id"] == job_id
        assert len(body["questions"]) == 1
        assert body["questions"][0]["id"] == "q1"


def test_submit_clarifications_refines_plan_and_reseeds_actions(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    client = TestClient(app)
    refined = RemediationPlan(
        recommended_actions=["Apply temporary connection throttling"],
        next_checks=["Validate timeout rate over 10 minutes"],
        risk_if_unresolved="Checkout remains unstable",
        recommended_severities=["critical"],
        check_severities=["not-valid"],
    )

    with patch("remediator.agent.generate_remediation", return_value=refined):
        response = client.post(
            f"/api/jobs/{job_id}/clarify",
            json={"answers": {"q1": "yes"}},
        )
        assert response.status_code == 200, response.text
        assert response.json()["refined"] is True

    db = get_database()
    actions = db.list_remediation_actions(job_id)
    answers = db.get_clarification_answers(job_id)
    row = db.get_job(job_id, clerk_user_id="dev_user")
    db.close()

    assert answers == {"q1": "yes"}
    assert len(actions) == 2
    assert actions[0]["action_type"] == "recommended"
    assert actions[0]["severity"] == "critical"
    assert actions[1]["action_type"] == "check"
    assert actions[1]["severity"] == "medium"  # fallback for high incidents
    assert "Apply temporary connection throttling" in (row or {}).get("analysis_json", "")


def test_patch_action_validates_and_updates_action_fields(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    db = get_database()
    action_id = db.list_remediation_actions(job_id)[0]["id"]
    db.close()

    client = TestClient(app)
    bad = client.patch(
        f"/api/jobs/{job_id}/actions/{action_id}",
        json={"status": "not-a-status"},
    )
    assert bad.status_code == 400

    ok = client.patch(
        f"/api/jobs/{job_id}/actions/{action_id}",
        json={"status": "in_progress", "assigned_to": "oncall-1", "notes": "working now"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["updated"] is True

    verify = get_database()
    updated = verify.get_action(action_id)
    verify.close()
    assert updated is not None
    assert updated["status"] == "in_progress"
    assert updated["assigned_to"] == "oncall-1"


def test_evaluate_action_findings_satisfied_marks_action_done(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    db = get_database()
    action_id = db.list_remediation_actions(job_id)[0]["id"]
    db.close()

    client = TestClient(app)
    verdict = ActionEvaluationResult(
        satisfied=True,
        response="Looks resolved based on provided findings.",
        next_step=None,
    )
    with patch("remediator.agent.evaluate_findings", return_value=verdict):
        response = client.post(
            f"/api/jobs/{job_id}/actions/{action_id}/evaluate",
            json={"findings": "Timeouts dropped to near zero after pool update"},
        )
        assert response.status_code == 201, response.text
        assert response.json()["satisfied"] is True

    verify = get_database()
    updated = verify.get_action(action_id)
    verify.close()
    assert updated is not None
    assert updated["status"] == "done"
    assert updated["eval_response"] == verdict.response


def test_evaluate_action_findings_unsatisfied_creates_trail_action(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    db = get_database()
    action_id = db.list_remediation_actions(job_id)[0]["id"]
    db.close()

    verdict = ActionEvaluationResult(
        satisfied=False,
        response="Still seeing instability in one region.",
        next_step="Check DB replica lag and failover health",
    )
    client = TestClient(app)
    with patch("remediator.agent.evaluate_findings", return_value=verdict):
        response = client.post(
            f"/api/jobs/{job_id}/actions/{action_id}/evaluate",
            json={"findings": "Some improvement, but intermittent errors remain"},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["satisfied"] is False
        assert body["child_action_id"] is not None

    verify = get_database()
    actions = verify.list_remediation_actions(job_id)
    verify.close()
    assert any(
        a["parent_action_id"] == action_id
        and a["action_text"] == "Check DB replica lag and failover health"
        for a in actions
    )


def test_remediation_followup_generates_followup_actions_and_checks(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    db = get_database()
    anchor = db.list_remediation_actions(job_id)[0]["id"]
    db.close()

    followup = RemediationFollowUp(
        followup_actions=["Temporarily disable heavy write path"],
        followup_severities=["high"],
        followup_checks=["Confirm queue depth trends down"],
        check_severities=["medium"],
        updated_risk="Residual risk remains moderate",
    )
    client = TestClient(app)
    with patch("remediator.agent.generate_followup_actions", return_value=followup):
        response = client.post(
            f"/api/jobs/{job_id}/remediation-followup",
            json={
                "additional_context": "Replica lag spikes during peak traffic",
                "anchor_action_id": anchor,
            },
        )
        assert response.status_code == 201, response.text
        assert response.json()["new_actions_count"] == 2

    verify = get_database()
    actions = verify.list_remediation_actions(job_id)
    verify.close()
    assert any(a["action_type"] == "followup" for a in actions)
    assert any(a["action_type"] == "followup_check" for a in actions)


def test_pir_generate_and_get_endpoints_roundtrip(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    pir = PostIncidentReview(
        job_id=job_id,
        timeline="13:00 alert fired, 13:05 triage, 13:15 mitigation",
        what_went_wrong="Connection pool saturation under burst traffic",
        what_went_right="Mitigation and coordination were fast",
        action_summary=["Scaled DB pool", "Added watch metrics"],
        prevention_steps=["Add autoscaling triggers", "Tighten alerting thresholds"],
        lessons_learned="Capacity assumptions were too optimistic",
    )

    client = TestClient(app)
    with patch("remediator.agent.generate_pir", return_value=pir):
        generated = client.post(f"/api/jobs/{job_id}/pir")
        assert generated.status_code == 201, generated.text
        assert generated.json()["job_id"] == job_id

    fetched = client.get(f"/api/jobs/{job_id}/pir")
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["what_went_wrong"] == pir.what_went_wrong


def test_replay_endpoints_return_frames_and_explanations(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    replay = ReplayResponse(
        job_id=job_id,
        status="completed",
        frames=[
            ReplayFrame(index=0, stage="queued", title="Queued"),
            ReplayFrame(index=1, stage="root_cause", title="Root Cause"),
        ],
    )

    client = TestClient(app)
    with patch("api.main.build_replay", return_value=replay):
        get_resp = client.get(f"/api/jobs/{job_id}/replay")
        assert get_resp.status_code == 200, get_resp.text
        assert len(get_resp.json()["frames"]) == 2

    explanation = ReplayExplainResponse(
        frame_index=1,
        explanation="Root cause stage connected DB timeouts to pool pressure",
        confidence="high",
        evidence=["pool wait exceeded"],
    )
    with patch("api.main.build_replay", return_value=replay), patch(
        "api.main.explain_replay_frame", return_value=explanation
    ):
        explain_resp = client.post(
            f"/api/jobs/{job_id}/replay/explain",
            json={"frame_index": 1},
        )
        assert explain_resp.status_code == 200, explain_resp.text
        assert explain_resp.json()["confidence"] == "high"


def test_replay_explain_validates_frame_index_range(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    replay = ReplayResponse(
        job_id=job_id,
        status="completed",
        frames=[ReplayFrame(index=0, stage="queued", title="Queued")],
    )
    client = TestClient(app)
    with patch("api.main.build_replay", return_value=replay):
        response = client.post(
            f"/api/jobs/{job_id}/replay/explain",
            json={"frame_index": 3},
        )
        assert response.status_code == 422
        assert response.json()["detail"] == "frame_index out of range"


def test_integrations_create_list_and_delete(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    client = TestClient(app)
    bad = client.post(
        "/api/integrations",
        json={"type": "invalid", "config": {}, "enabled": True},
    )
    assert bad.status_code == 400

    created = client.post(
        "/api/integrations",
        json={
            "type": "generic_webhook",
            "config": {"webhook_url": "https://example.test/webhook"},
            "enabled": True,
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["integration_id"]

    listed = client.get("/api/integrations")
    assert listed.status_code == 200
    assert any(i["id"] == integration_id for i in listed.json())

    deleted = client.delete(f"/api/integrations/{integration_id}")
    assert deleted.status_code == 204

    listed_after = client.get("/api/integrations")
    assert all(i["id"] != integration_id for i in listed_after.json())


def test_followup_create_list_send_pending_and_delete(
    isolated_local_db: None, auth_disabled: None
) -> None:
    from api.main import app

    _, job_id = _seed_completed_job()
    client = TestClient(app)
    create_resp = client.post(
        f"/api/jobs/{job_id}/follow-ups",
        json={
            "user_email": "ops@example.com",
            "remind_at": "2026-04-27T15:00:00+00:00",
            "message": "Re-check error budget in one hour",
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    follow_up_id = create_resp.json()["follow_up_id"]

    listed = client.get(f"/api/jobs/{job_id}/follow-ups")
    assert listed.status_code == 200
    assert any(f["id"] == follow_up_id for f in listed.json())

    with patch("common.scheduler.ReminderScheduler.process_all_pending", return_value=(1, 0)):
        send_resp = client.post("/api/follow-ups/send-pending")
        assert send_resp.status_code == 200
        assert send_resp.json() == {"sent": 1, "failed": 0}

    deleted = client.delete(f"/api/jobs/{job_id}/follow-ups/{follow_up_id}")
    assert deleted.status_code == 204
