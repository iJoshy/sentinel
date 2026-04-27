"""Orchestration pipeline shared by API and planner lambda."""

from __future__ import annotations

import json
import logging
import os
import re

from common.config import active_model
from common.models import IncidentAnalysis, IncidentInput, JobRunResponse
from common.similarity import find_similar_incidents
from common.store import Database, get_database
from investigator.agent import investigate_root_cause
from normalizer.agent import normalize_incident
from remediator.agent import generate_remediation
from summarizer.agent import summarize_incident

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def _integration_notify_severities() -> frozenset[str]:
    """Comma-separated severities that trigger outbound integrations (default: high,critical)."""
    raw = (os.getenv("INTEGRATION_NOTIFY_SEVERITIES", "high,critical") or "").strip()
    raw = raw.strip('"').strip("'")
    parts = {p.strip().lower() for p in raw.split(",") if p.strip()}
    chosen = parts & _VALID_SEVERITIES
    return frozenset(chosen) if chosen else frozenset({"high", "critical"})


def _build_action_scorecard(
    *,
    action_text: str,
    action_type: str,
    root_cause_summary: str,
    root_confidence: str,
    evidence_pool: list[str],
) -> dict[str, object]:
    """Derive trust metadata for one remediation action.

    This is intentionally heuristic: it gives operators a consistent, evidence-linked
    confidence signal even when the LLM does not emit per-action confidence fields.
    """
    tokens = {t for t in re.findall(r"[a-z0-9]+", action_text.lower()) if len(t) >= 4}
    matched: list[str] = []
    for snippet in evidence_pool:
        s = (snippet or "").strip()
        if not s:
            continue
        s_lower = s.lower()
        if tokens and any(tok in s_lower for tok in tokens):
            matched.append(s)
    if not matched:
        matched = [s for s in evidence_pool[:2] if (s or "").strip()]

    confidence = (root_confidence or "medium").lower()
    if action_type in {"check", "followup_check"} and confidence == "high":
        confidence = "medium"
    if not matched and confidence == "high":
        confidence = "medium"

    evidence_count = len(matched)
    evidence_label = (
        f"{evidence_count} supporting log snippet"
        + ("" if evidence_count == 1 else "s")
        if evidence_count
        else "no direct supporting log snippets"
    )
    rationale = f"This step targets the suspected root cause ({root_cause_summary}) and is backed by {evidence_label}."
    risk_if_wrong = (
        "Could delay mitigation and consume responder time without reducing impact."
        if action_type in {"recommended", "followup", "trail"}
        else "Could create false confidence that the incident is resolved when it is not."
    )
    return {
        "confidence": (
            confidence if confidence in {"low", "medium", "high"} else "medium"
        ),
        "evidence": matched[:3],
        "rationale": rationale,
        "risk_if_wrong": risk_if_wrong,
    }


def run_job(
    job_id: str, db: Database | None = None, clerk_user_id: str | None = None
) -> JobRunResponse:
    """Execute the full multi-agent workflow for one job."""

    owned_db = False
    if db is None:
        db = get_database()
        owned_db = True

    try:
        row = db.get_job_with_incident(job_id, clerk_user_id=clerk_user_id)
        if not row:
            return JobRunResponse(
                incident_id="", job_id=job_id, status="failed", error="Job not found"
            )

        status = row.get("status")
        if status == "processing":
            return JobRunResponse(
                incident_id=row["incident_id"], job_id=job_id, status="processing"
            )
        if status == "completed" and row.get("analysis_json"):
            try:
                analysis = IncidentAnalysis.model_validate_json(row["analysis_json"])
                return JobRunResponse(
                    incident_id=row["incident_id"],
                    job_id=job_id,
                    status="completed",
                    analysis=analysis,
                )
            except Exception:  # noqa: BLE001
                pass

        db.update_job_status(job_id, "processing")
        db.set_job_stage(job_id, "queued", "Starting pipeline")

        db.set_job_stage(job_id, "normalize", "Sanitizing and structuring input")
        normalized = normalize_incident(row["raw_text"])
        db.update_incident_sanitization(
            row["incident_id"],
            normalized.normalized_text,
            normalized.guardrails.model_dump(),
        )

        try:
            uid = row.get("clerk_user_id") or clerk_user_id or "anonymous"
            past = db.list_incidents(limit=100, clerk_user_id=uid)
            similar = find_similar_incidents(
                normalized.normalized_text,
                past,
                exclude_id=row["incident_id"],
            )
            if similar:
                db.set_similar_incidents(job_id, similar)
        except Exception:  # noqa: BLE001
            logger.warning("Similarity lookup failed; continuing without it")

        db.set_job_stage(job_id, "summarize", "Generating summary and severity")
        summary = summarize_incident(normalized)

        db.set_job_stage(job_id, "root_cause", "Investigating likely root cause")
        root_cause = investigate_root_cause(normalized, summary)

        db.set_job_stage(job_id, "remediate", "Building remediation plan")
        remediation = generate_remediation(normalized, summary, root_cause)

        analysis = IncidentAnalysis(
            incident_id=row["incident_id"],
            job_id=job_id,
            summary=summary,
            root_cause=root_cause,
            remediation=remediation,
            guardrails=normalized.guardrails,
            models={"model": active_model()},
        )

        db.save_analysis(job_id, analysis)

        try:
            incident_severity = summary.severity  # critical / high / medium / low
            _lower = {
                "critical": "high",
                "high": "medium",
                "medium": "low",
                "low": "low",
            }
            fallback_check_sev = _lower.get(incident_severity, "medium")

            valid_severities = {"critical", "high", "medium", "low"}

            # Build per-action severity lists, padding with incident severity if LLM omitted entries.
            rec_sevs = list(remediation.recommended_severities)
            while len(rec_sevs) < len(remediation.recommended_actions):
                rec_sevs.append(incident_severity)

            chk_sevs = list(remediation.check_severities)
            while len(chk_sevs) < len(remediation.next_checks):
                chk_sevs.append(fallback_check_sev)

            for text, sev in zip(remediation.recommended_actions, rec_sevs):
                sev = sev if sev in valid_severities else incident_severity
                scorecard = _build_action_scorecard(
                    action_text=text,
                    action_type="recommended",
                    root_cause_summary=root_cause.likely_root_cause,
                    root_confidence=root_cause.confidence,
                    evidence_pool=list(
                        root_cause.supporting_evidence or normalized.evidence_snippets
                    ),
                )
                db.seed_remediation_actions(
                    job_id,
                    [text],
                    action_type="recommended",
                    severity=sev,
                    confidence=str(scorecard["confidence"]),
                    evidence=list(scorecard["evidence"]),
                    rationale=str(scorecard["rationale"]),
                    risk_if_wrong=str(scorecard["risk_if_wrong"]),
                )

            for text, sev in zip(remediation.next_checks, chk_sevs):
                sev = sev if sev in valid_severities else fallback_check_sev
                scorecard = _build_action_scorecard(
                    action_text=text,
                    action_type="check",
                    root_cause_summary=root_cause.likely_root_cause,
                    root_confidence=root_cause.confidence,
                    evidence_pool=list(
                        root_cause.supporting_evidence or normalized.evidence_snippets
                    ),
                )
                db.seed_remediation_actions(
                    job_id,
                    [text],
                    action_type="check",
                    severity=sev,
                    confidence=str(scorecard["confidence"]),
                    evidence=list(scorecard["evidence"]),
                    rationale=str(scorecard["rationale"]),
                    risk_if_wrong=str(scorecard["risk_if_wrong"]),
                )

        except Exception:  # noqa: BLE001
            logger.warning("Failed to seed remediation actions; continuing")

        try:
            owner = str(row.get("clerk_user_id") or "").strip()
            param_uid = (clerk_user_id or "").strip()
            if not owner:
                owner = param_uid or "anonymous"
                param_uid = ""
            alternate = param_uid if param_uid and param_uid != owner else None
            _fire_integrations(
                job_id,
                analysis,
                db,
                owner,
                incident_title=str(row.get("title") or "").strip(),
                incident_source=str(row.get("source") or "").strip(),
                alternate_user_id=alternate,
            )
        except Exception:  # noqa: BLE001
            logger.exception("Integration dispatch failed for job_id=%s; continuing", job_id)

        db.set_job_stage(job_id, "completed", "Analysis ready")
        return JobRunResponse(
            incident_id=row["incident_id"],
            job_id=job_id,
            status="completed",
            analysis=analysis,
        )

    except Exception as exc:  # noqa: BLE001
        db.update_job_status(job_id, "failed", str(exc))
        row = db.get_job(job_id, clerk_user_id=clerk_user_id) or {"incident_id": ""}
        try:
            db.set_job_stage(job_id, "failed", str(exc))
        except Exception:  # noqa: BLE001
            pass
        return JobRunResponse(
            incident_id=row.get("incident_id", ""),
            job_id=job_id,
            status="failed",
            error=str(exc),
        )
    finally:
        if owned_db:
            db.close()


def _fire_integrations(
    job_id: str,
    analysis: "IncidentAnalysis",
    db: Database,
    clerk_user_id: str,
    *,
    incident_title: str = "",
    incident_source: str = "",
    alternate_user_id: str | None = None,
) -> None:
    """Dispatch configured integrations if analysis severity warrants it.

    Pass ``incident_title`` / ``incident_source`` from the job row (``get_job_with_incident``)
    so webhooks always get the correct label without a second DB lookup that can fail on
    tenant id mismatches (e.g. Lambda ``run_job(job_id, db)`` with no Clerk context).

    If ``alternate_user_id`` is set (e.g. API caller id differs from the job row owner),
    integrations for both users are merged so Slack/webhooks saved under either id still run.
    """
    from integrations.dispatcher import dispatch_all

    user_ids: list[str] = []
    if clerk_user_id:
        user_ids.append(clerk_user_id)
    if alternate_user_id and alternate_user_id not in user_ids:
        user_ids.append(alternate_user_id)

    seen: set[str] = set()
    integrations: list[dict] = []
    for uid in user_ids:
        for row in db.list_integrations(uid):
            rid = row.get("id")
            if rid:
                if rid in seen:
                    continue
                seen.add(rid)
            integrations.append(row)

    if not integrations:
        logger.info(
            "Outbound integrations skipped job_id=%s: no integrations for user_ids=%s",
            job_id,
            user_ids,
        )
        return
    severity = str(analysis.summary.severity or "medium").strip().lower()
    notify = _integration_notify_severities()
    if severity not in notify:
        logger.info(
            "Outbound integrations skipped job_id=%s: severity=%s not in INTEGRATION_NOTIFY_SEVERITIES (%s)",
            job_id,
            severity,
            ",".join(sorted(notify)),
        )
        return
    logger.info(
        "Dispatching outbound integrations job_id=%s user_ids=%s severity=%s count=%s",
        job_id,
        user_ids,
        severity,
        len(integrations),
    )
    dispatch_all(
        integrations,
        analysis,
        incident_title=incident_title,
        incident_source=incident_source,
    )


def create_incident_and_job(
    payload: IncidentInput,
    db: Database | None = None,
    clerk_user_id: str = "anonymous",
) -> tuple[str, str]:
    """Create incident/job records in pending state."""

    owned_db = False
    if db is None:
        db = get_database()  # type: ignore[assignment]
        owned_db = True

    try:
        incident_id = db.create_incident(
            text=payload.text,
            title=payload.title,
            source=payload.source,
            clerk_user_id=clerk_user_id,
        )
        job_id = db.create_job(incident_id=incident_id, clerk_user_id=clerk_user_id)
        return incident_id, job_id
    finally:
        if owned_db:
            db.close()


def parse_analysis(job_row: dict) -> dict | None:
    """Parse analysis payload from DB row."""

    raw = job_row.get("analysis_json")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None
