"""Provider-agnostic log ingestion for enterprise Live Incident."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from common.live_correlation import correlate_application_signals
from common.store import Database


_SIGNAL_PATTERNS: list[dict[str, Any]] = [
    {
        "type": "oom",
        "regex": re.compile(r"(oom|out of memory|killed process)", re.I),
        "severity": "critical",
    },
    {
        "type": "fatal_runtime_failure",
        "regex": re.compile(r"(panic|fatal|service down|outage)", re.I),
        "severity": "critical",
    },
    {
        "type": "auth_failure_burst",
        "regex": re.compile(r"(\b401\b|\b403\b|forbidden|unauthor|access denied|permission denied|invalid token|\bjwt\b)", re.I),
        "severity": "high",
    },
    {
        "type": "database_error",
        "regex": re.compile(r"(database unavailable|db timeout|connection refused|could not connect|sqlstate|postgres)", re.I),
        "severity": "high",
    },
    {
        "type": "timeout_spike",
        "regex": re.compile(r"(timeout|timed out|deadline exceeded|upstream failure|504|503)", re.I),
        "severity": "high",
    },
    {
        "type": "throttle_spike",
        "regex": re.compile(r"(throttl|rate limit|too many requests|429)", re.I),
        "severity": "high",
    },
    {
        "type": "application_error",
        "regex": re.compile(r"(exception|traceback|error|failed)", re.I),
        "severity": "medium",
    },
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _message_from_gcp_entry(entry: dict[str, Any]) -> str:
    for key in ("textPayload", "message"):
        value = entry.get(key)
        if value:
            return str(value)
    if entry.get("jsonPayload"):
        payload = entry["jsonPayload"]
        if isinstance(payload, dict):
            for key in ("message", "msg", "error", "text"):
                if payload.get(key):
                    return str(payload[key])
        return json.dumps(payload, sort_keys=True)[:10000]
    if entry.get("protoPayload"):
        return json.dumps(entry["protoPayload"], sort_keys=True)[:10000]
    return json.dumps(entry, sort_keys=True)[:10000]


def _gcp_service_name(entry: dict[str, Any]) -> str | None:
    resource = entry.get("resource") or {}
    labels = resource.get("labels") or {}
    flat_labels = entry.get("labels") or {}
    for key in (
        "service_name",
        "container_name",
        "pod_name",
        "function_name",
        "job_name",
    ):
        if labels.get(key):
            return str(labels[key])
        if flat_labels.get(key):
            return str(flat_labels[key])
    return None


def _first_present(*values: Any) -> str | None:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _nested_get(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _extract_request_id(payload: dict[str, Any], labels: dict[str, Any]) -> str | None:
    json_payload = payload.get("jsonPayload") if isinstance(payload.get("jsonPayload"), dict) else {}
    http_request = payload.get("httpRequest") if isinstance(payload.get("httpRequest"), dict) else {}
    return _first_present(
        labels.get("request_id"),
        labels.get("requestId"),
        labels.get("x-request-id"),
        json_payload.get("request_id"),
        json_payload.get("requestId"),
        json_payload.get("correlation_id"),
        http_request.get("requestId"),
        _nested_get(payload, ("protoPayload", "requestMetadata", "requestId")),
    )


def _extract_deployment_version(payload: dict[str, Any], labels: dict[str, Any]) -> str | None:
    json_payload = payload.get("jsonPayload") if isinstance(payload.get("jsonPayload"), dict) else {}
    candidates = (
        "deployment_version",
        "version",
        "revision",
        "revision_name",
        "release",
        "build_sha",
        "commit_sha",
        "app.kubernetes.io/version",
        "k8s-pod/app_kubernetes_io/version",
    )
    for key in candidates:
        value = _first_present(labels.get(key), labels.get(f"resource.{key}"), json_payload.get(key))
        if value:
            return value
    return None


def decode_gcp_pubsub_push(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Decode a GCP Pub/Sub push body into Cloud Logging entries."""

    message = payload.get("message") or payload
    data = message.get("data")
    if not data:
        return []
    decoded = base64.b64decode(str(data)).decode("utf-8")
    entry = json.loads(decoded)
    if isinstance(entry, list):
        return [item for item in entry if isinstance(item, dict)]
    if isinstance(entry, dict):
        return [entry]
    return []


def normalize_gcp_logging_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for entry in entries:
        labels = {}
        if isinstance(entry.get("labels"), dict):
            labels.update(entry["labels"])
        resource = entry.get("resource") or {}
        if isinstance(resource.get("labels"), dict):
            labels.update({f"resource.{k}": v for k, v in resource["labels"].items()})
        service_name = _gcp_service_name(entry)
        if service_name:
            labels["service_name"] = service_name
        request_id = _extract_request_id(entry, labels)
        deployment_version = _extract_deployment_version(entry, labels)
        if request_id:
            labels["request_id"] = request_id
        if deployment_version:
            labels["deployment_version"] = deployment_version
        records.append(
            {
                "timestamp": entry.get("timestamp") or entry.get("receiveTimestamp"),
                "message": _message_from_gcp_entry(entry),
                "severity": str(entry.get("severity") or "default").lower(),
                "trace_id": entry.get("trace"),
                "request_id": request_id,
                "deployment_version": deployment_version,
                "labels": labels,
                "payload": entry,
                "service_name": service_name,
            }
        )
    return records


def _detect_signal(message: str, severity: str) -> tuple[str, str] | None:
    for pattern in _SIGNAL_PATTERNS:
        if pattern["regex"].search(message):
            return pattern["type"], pattern["severity"]
    if severity.lower() in {"critical", "alert", "emergency"}:
        return "critical_log", "critical"
    if severity.lower() in {"error"}:
        return "application_error", "medium"
    return None


def _fingerprint(application_id: str, service_id: str, signal_type: str, message: str) -> str:
    normalized = re.sub(r"\b[0-9a-f]{8,}\b", "<id>", message.lower())
    normalized = re.sub(r"\d+", "<n>", normalized)
    normalized = normalized[:220]
    raw = f"{application_id}|{service_id}|{signal_type}|{normalized}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]


def ingest_live_records(
    *,
    db: Database,
    clerk_user_id: str,
    application_id: str,
    provider: str,
    records: list[dict[str, Any]],
    service_id: str | None = None,
    log_source_id: str | None = None,
    correlate: bool = True,
    run_analysis_async: bool = True,
) -> dict[str, Any]:
    """Store normalized log records and create/update cheap live signals."""

    app = db.get_live_application(application_id, clerk_user_id, include_children=False)
    if not app:
        return {"status": "error", "reason": "application_not_found", "accepted": 0, "signals": []}

    accepted = 0
    signals: list[dict[str, Any]] = []
    warnings: list[str] = []

    for record in records:
        message = str(record.get("message") or "").strip()
        if not message:
            continue
        labels = record.get("labels") if isinstance(record.get("labels"), dict) else {}
        service_name = record.get("service_name") or labels.get("service_name")
        request_id = _first_present(record.get("request_id"), labels.get("request_id"), labels.get("requestId"))
        deployment_version = _first_present(
            record.get("deployment_version"),
            labels.get("deployment_version"),
            labels.get("version"),
            labels.get("revision_name"),
            labels.get("resource.revision_name"),
        )
        source = db.find_live_log_source_for_event(
            application_id,
            clerk_user_id,
            provider=provider,
            service_name=str(service_name) if service_name else None,
            log_source_id=log_source_id,
        )
        resolved_service_id = service_id or (source or {}).get("service_id")
        resolved_source_id = log_source_id or (source or {}).get("id")
        if not resolved_service_id:
            warnings.append(f"No service/log source matched event: {message[:120]}")
            continue
        if not db.get_live_service(resolved_service_id, clerk_user_id):
            warnings.append(f"Service not found for event: {resolved_service_id}")
            continue

        event = db.create_live_log_event(
            application_id=application_id,
            service_id=resolved_service_id,
            log_source_id=resolved_source_id,
            clerk_user_id=clerk_user_id,
            provider=provider,
            event_timestamp=record.get("timestamp"),
            severity=str(record.get("severity") or "default"),
            message=message[:10000],
            trace_id=record.get("trace_id"),
            labels=labels,
            payload=record.get("payload") if isinstance(record.get("payload"), dict) else {},
        )
        accepted += 1

        detected = _detect_signal(message, event["severity"])
        if not detected:
            continue
        signal_type, signal_severity = detected
        evidence = [
            {
                "event_id": event["id"],
                "timestamp": event.get("event_timestamp") or event["received_at"],
                "message": message[:500],
                "severity": event["severity"],
                "trace_id": event.get("trace_id"),
                "request_id": request_id,
                "deployment_version": deployment_version,
            }
        ]
        signal = db.upsert_live_signal(
            application_id=application_id,
            service_id=resolved_service_id,
            log_source_id=resolved_source_id,
            clerk_user_id=clerk_user_id,
            signal_type=signal_type,
            severity=signal_severity,
            fingerprint=_fingerprint(application_id, resolved_service_id, signal_type, message),
            evidence=evidence,
            window_start=record.get("timestamp") or event["received_at"],
            window_end=_now_iso(),
        )
        signals.append(signal)

    correlation = None
    if correlate and signals:
        correlation = correlate_application_signals(
            db=db,
            clerk_user_id=clerk_user_id,
            application_id=application_id,
            run_analysis_async=run_analysis_async,
        )

    return {
        "status": "accepted",
        "accepted": accepted,
        "signals": signals,
        "warnings": warnings,
        "correlation": correlation,
    }
