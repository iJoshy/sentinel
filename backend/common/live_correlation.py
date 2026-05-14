"""Cross-service correlation for enterprise Live Incident signals."""

from __future__ import annotations

import hashlib
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from common.models import IncidentInput
from common.pipeline import create_incident_and_job, run_job
from common.store import Database


_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _severity_rank(value: str | None) -> int:
    return _SEVERITY_ORDER.get((value or "medium").lower(), 2)


def _max_severity(signals: list[dict[str, Any]]) -> str:
    best = "medium"
    for signal in signals:
        sev = str(signal.get("severity") or "medium").lower()
        if _severity_rank(sev) > _severity_rank(best):
            best = sev
    return best


def _recent_signals(
    db: Database,
    application_id: str,
    clerk_user_id: str,
    *,
    window_minutes: int,
) -> list[dict[str, Any]]:
    cutoff = _now() - timedelta(minutes=window_minutes)
    signals = db.list_live_signals(application_id, clerk_user_id, limit=100)
    recent = []
    for signal in signals:
        updated_at = _parse_dt(signal.get("updated_at"))
        if updated_at is None or updated_at >= cutoff:
            recent.append(signal)
    return recent


def _should_open_incident(signals: list[dict[str, Any]], min_signals: int, min_services: int) -> bool:
    if not signals:
        return False
    if any(str(signal.get("severity") or "").lower() == "critical" for signal in signals):
        return True
    services = {str(signal.get("service_id")) for signal in signals if signal.get("service_id")}
    return len(signals) >= min_signals and len(services) >= min_services


def _service_label(signal: dict[str, Any]) -> str:
    return str(signal.get("service_name") or signal.get("service_id") or "unknown-service")


def _evidence_values(signal: dict[str, Any], key: str) -> set[str]:
    values: set[str] = set()
    for item in signal.get("evidence") or []:
        value = item.get(key)
        if value is not None and str(value).strip():
            values.add(str(value).strip())
    return values


def _trace_ids(signal: dict[str, Any]) -> set[str]:
    return _evidence_values(signal, "trace_id")


def _request_ids(signal: dict[str, Any]) -> set[str]:
    return _evidence_values(signal, "request_id")


def _deployment_versions(signal: dict[str, Any]) -> set[str]:
    return _evidence_values(signal, "deployment_version")


def _first_seen(signal: dict[str, Any]) -> datetime | None:
    candidates = [_parse_dt(signal.get("window_start"))]
    candidates.extend(_parse_dt(item.get("timestamp")) for item in signal.get("evidence") or [])
    valid = [item for item in candidates if item is not None]
    return min(valid) if valid else _parse_dt(signal.get("updated_at"))


def _criticality_score(value: str | None) -> int:
    return {"low": 0, "medium": 1, "high": 3, "critical": 5}.get((value or "medium").lower(), 1)


def _dependency_score(signal: dict[str, Any]) -> int:
    try:
        order = int(signal.get("dependency_order") or 0)
    except (TypeError, ValueError):
        order = 0
    # Lower dependency_order means the service is earlier/upstream in the application flow.
    return max(0, 20 - min(order, 20))


def _id_service_counts(signals: list[dict[str, Any]], extractor: Any) -> Counter[str]:
    pairs: Counter[str] = Counter()
    owners: dict[str, set[str]] = {}
    for signal in signals:
        service_id = str(signal.get("service_id") or _service_label(signal))
        for value in extractor(signal):
            owners.setdefault(value, set()).add(service_id)
    for value, service_ids in owners.items():
        pairs[value] = len(service_ids)
    return pairs


def _earliest_signal_for_values(signals: list[dict[str, Any]], extractor: Any) -> dict[str, str]:
    earliest: dict[str, tuple[datetime, str]] = {}
    for signal in signals:
        signal_id = str(signal.get("id") or signal.get("fingerprint") or _service_label(signal))
        first_seen = _first_seen(signal)
        if first_seen is None:
            continue
        for value in extractor(signal):
            current = earliest.get(value)
            if current is None or first_seen < current[0]:
                earliest[value] = (first_seen, signal_id)
    return {value: signal_id for value, (_, signal_id) in earliest.items()}


def rank_suspected_source(signals: list[dict[str, Any]]) -> dict[str, Any]:
    """Rank the most likely source signal using topology and correlation context."""

    if not signals:
        return {"signal": {}, "score": 0, "reason": "no signals available", "candidates": []}

    trace_counts = _id_service_counts(signals, _trace_ids)
    request_counts = _id_service_counts(signals, _request_ids)
    deployment_counts = _id_service_counts(signals, _deployment_versions)
    earliest_trace = _earliest_signal_for_values(signals, _trace_ids)
    earliest_request = _earliest_signal_for_values(signals, _request_ids)
    first_seen_values = [_first_seen(signal) for signal in signals]
    earliest_overall = min([value for value in first_seen_values if value is not None], default=None)

    candidates: list[dict[str, Any]] = []
    for signal in signals:
        signal_id = str(signal.get("id") or signal.get("fingerprint") or _service_label(signal))
        reasons: list[str] = []
        score = 0.0

        severity_points = _severity_rank(signal.get("severity")) * 12
        score += severity_points
        reasons.append(f"severity {signal.get('severity') or 'medium'} (+{severity_points})")

        event_points = min(int(signal.get("event_count") or 0), 12)
        score += event_points
        if event_points:
            reasons.append(f"{int(signal.get('event_count') or 0)} matching event(s) (+{event_points})")

        dependency_points = _dependency_score(signal)
        score += dependency_points
        reasons.append(f"dependency order {int(signal.get('dependency_order') or 0)} (+{dependency_points})")

        criticality_points = _criticality_score(signal.get("service_criticality"))
        score += criticality_points
        if criticality_points:
            reasons.append(f"{signal.get('service_criticality') or 'medium'} criticality (+{criticality_points})")

        shared_traces = [value for value in _trace_ids(signal) if trace_counts.get(value, 0) > 1]
        if shared_traces:
            trace_points = 18 + min(len(shared_traces), 3) * 3
            score += trace_points
            reasons.append(f"shared trace/request path across services (+{trace_points})")
            if any(earliest_trace.get(value) == signal_id for value in shared_traces):
                score += 12
                reasons.append("earliest service seen on shared trace (+12)")

        shared_requests = [value for value in _request_ids(signal) if request_counts.get(value, 0) > 1]
        if shared_requests:
            request_points = 14 + min(len(shared_requests), 3) * 2
            score += request_points
            reasons.append(f"shared request id across services (+{request_points})")
            if any(earliest_request.get(value) == signal_id for value in shared_requests):
                score += 10
                reasons.append("earliest service seen on shared request id (+10)")

        deployments = _deployment_versions(signal)
        if deployments:
            score += 8
            reasons.append("deployment version present in signal (+8)")
            shared_deployments = [value for value in deployments if deployment_counts.get(value, 0) > 1]
            if shared_deployments:
                score += 6
                reasons.append("same deployment version appears across impacted services (+6)")
            if earliest_overall is not None and _first_seen(signal) == earliest_overall:
                score += 8
                reasons.append("deployed service is first signal in incident window (+8)")

        if earliest_overall is not None and _first_seen(signal) == earliest_overall:
            score += 6
            reasons.append("first signal in correlation window (+6)")

        candidates.append(
            {
                "signal": signal,
                "service_id": signal.get("service_id"),
                "service_name": _service_label(signal),
                "score": round(score, 2),
                "reasons": reasons,
                "first_seen": (_first_seen(signal).isoformat() if _first_seen(signal) else None),
            }
        )

    candidates.sort(
        key=lambda item: (
            item["score"],
            _severity_rank(item["signal"].get("severity")),
            int(item["signal"].get("event_count") or 0),
        ),
        reverse=True,
    )
    winner = candidates[0]
    return {
        "signal": winner["signal"],
        "score": winner["score"],
        "reason": "; ".join(winner["reasons"]),
        "candidates": [
            {
                "service_id": item["service_id"],
                "service_name": item["service_name"],
                "score": item["score"],
                "reasons": item["reasons"][:5],
                "first_seen": item["first_seen"],
            }
            for item in candidates[:5]
        ],
    }


def _suspected_source(signals: list[dict[str, Any]]) -> dict[str, Any]:
    return rank_suspected_source(signals)["signal"]


def _incident_fingerprint(application_id: str, source_signal: dict[str, Any]) -> str:
    raw = "|".join(
        [
            application_id,
            str(source_signal.get("service_id") or ""),
            str(source_signal.get("signal_type") or ""),
            str(source_signal.get("fingerprint") or ""),
        ]
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def _build_evidence(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for signal in signals:
        service_name = signal.get("service_name") or signal.get("service_id")
        for item in signal.get("evidence") or []:
            evidence.append(
                {
                    "timestamp": item.get("timestamp"),
                    "log_group": str(service_name),
                    "message": str(item.get("message") or "")[:500],
                    "signal_type": signal.get("signal_type"),
                    "severity": signal.get("severity"),
                    "trace_id": item.get("trace_id"),
                    "request_id": item.get("request_id"),
                    "deployment_version": item.get("deployment_version"),
                }
            )
    return evidence[-12:]


def _build_incident_packet(
    application: dict[str, Any],
    signals: list[dict[str, Any]],
    source_profile: dict[str, Any],
) -> str:
    services = sorted({str(signal.get("service_name") or signal.get("service_id")) for signal in signals})
    source = source_profile.get("signal") or _suspected_source(signals)
    stamp = _now_iso()
    lines = [
        f"{stamp} ERROR live_correlation detected multi-service production issue",
        f"{stamp} ERROR application={application.get('name')} environment={application.get('environment')}",
        f"{stamp} ERROR suspected_source_service={source.get('service_name') or source.get('service_id')}",
        f"{stamp} ERROR suspected_source_score={source_profile.get('score')} reason={source_profile.get('reason')}",
        f"{stamp} ERROR affected_services={', '.join(services)}",
    ]
    for signal in signals:
        lines.append(
            f"{stamp} ERROR signal "
            f"{signal.get('service_name') or signal.get('service_id')}: "
            f"{signal.get('signal_type')} "
            f"severity={signal.get('severity')} "
            f"events={signal.get('event_count')} "
            f"dependency_order={signal.get('dependency_order')} "
            f"window_start={signal.get('window_start')}"
        )
    for candidate in source_profile.get("candidates") or []:
        lines.append(
            f"{stamp} ERROR candidate_source "
            f"{candidate.get('service_name')} score={candidate.get('score')} "
            f"first_seen={candidate.get('first_seen')}"
        )
    for item in _build_evidence(signals):
        metadata = []
        if item.get("trace_id"):
            metadata.append(f"trace_id={item.get('trace_id')}")
        if item.get("request_id"):
            metadata.append(f"request_id={item.get('request_id')}")
        if item.get("deployment_version"):
            metadata.append(f"deployment_version={item.get('deployment_version')}")
        suffix = f" {' '.join(metadata)}" if metadata else ""
        lines.append(f"{item.get('timestamp') or stamp} ERROR [{item.get('log_group')}] {item.get('message')}{suffix}")
    return "\n".join(lines)


def _start_background_analysis(job_id: str, clerk_user_id: str) -> None:
    threading.Thread(target=run_job, args=(job_id, None, clerk_user_id), daemon=True).start()


def correlate_application_signals(
    *,
    db: Database,
    clerk_user_id: str,
    application_id: str,
    window_minutes: int = 15,
    min_signals: int = 2,
    min_services: int = 2,
    run_analysis_async: bool = True,
) -> dict[str, Any]:
    """Open or update one live incident from recent cross-service signals."""

    application = db.get_live_application(application_id, clerk_user_id, include_children=False)
    if not application:
        return {"status": "error", "reason": "application_not_found"}

    signals = _recent_signals(db, application_id, clerk_user_id, window_minutes=window_minutes)
    if not _should_open_incident(signals, min_signals=min_signals, min_services=min_services):
        return {
            "status": "no_incident",
            "reason": "not_enough_correlated_signals",
            "signal_count": len(signals),
            "service_count": len({s.get("service_id") for s in signals if s.get("service_id")}),
        }

    source_profile = rank_suspected_source(signals)
    source_signal = source_profile["signal"]
    fingerprint = _incident_fingerprint(application_id, source_signal)
    severity = _max_severity(signals)
    service_names = sorted({str(signal.get("service_name") or signal.get("service_id")) for signal in signals})
    title = (
        f"{application.get('name')} {source_signal.get('signal_type')} "
        f"across {len(service_names)} service{'s' if len(service_names) != 1 else ''}"
    )
    combined_text = _build_incident_packet(application, signals, source_profile)
    evidence = _build_evidence(signals)
    refreshed_at = _now_iso()
    existing = db.get_live_incident_by_fingerprint(clerk_user_id, fingerprint)

    incident_id: str | None = None
    latest_job_id: str | None = None
    last_analysis_at: str | None = None

    if existing:
        incident_id = existing.get("incident_id")
        latest_job_id = existing.get("latest_job_id")
        if incident_id:
            db.update_incident_raw_text(incident_id, combined_text, title=title)
            latest_job_id = db.create_job(incident_id, clerk_user_id)
            last_analysis_at = refreshed_at
    else:
        payload = IncidentInput(title=title, source="live_correlation", text=combined_text)
        incident_id, latest_job_id = create_incident_and_job(payload, db, clerk_user_id=clerk_user_id)
        last_analysis_at = refreshed_at

    if latest_job_id and run_analysis_async:
        _start_background_analysis(latest_job_id, clerk_user_id)

    if existing:
        db.update_live_incident(
            existing["id"],
            title=title,
            severity=severity,
            source_log_groups=service_names,
            evidence=evidence,
            event_count=sum(int(signal.get("event_count") or 0) for signal in signals),
            incident_id=incident_id,
            latest_job_id=latest_job_id,
            last_seen_at=refreshed_at,
            last_analysis_at=last_analysis_at,
            status="open",
        )
        live_incident_id = existing["id"]
        action = "updated"
    else:
        live_incident_id = db.create_live_incident(
            clerk_user_id,
            fingerprint=fingerprint,
            title=title,
            severity=severity,
            source_log_groups=service_names,
            evidence=evidence,
            event_count=sum(int(signal.get("event_count") or 0) for signal in signals),
            incident_id=incident_id,
            latest_job_id=latest_job_id,
            first_seen_at=refreshed_at,
            last_seen_at=refreshed_at,
            last_analysis_at=last_analysis_at,
        )
        action = "created"

    return {
        "status": action,
        "live_incident_id": live_incident_id,
        "incident_id": incident_id,
        "job_id": latest_job_id,
        "fingerprint": fingerprint,
        "severity": severity,
        "signal_count": len(signals),
        "service_count": len(service_names),
        "source_reason": source_profile.get("reason"),
        "source_candidates": source_profile.get("candidates"),
        "signals": signals,
    }
