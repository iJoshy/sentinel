"""Google Cloud Function entrypoints for Sentinel."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from common.pipeline import run_job

logger = logging.getLogger(__name__)


def _decode_pubsub_payload(cloud_event: Any) -> dict[str, Any]:
    data = getattr(cloud_event, "data", None) or cloud_event
    message = (data or {}).get("message") or {}
    raw = message.get("data") or ""
    if not raw:
        return {}
    decoded = base64.b64decode(raw).decode("utf-8")
    return json.loads(decoded)


def pubsub_run_job(cloud_event: Any) -> dict[str, Any]:
    """Run one analysis job from a Pub/Sub CloudEvent."""

    payload = _decode_pubsub_payload(cloud_event)
    job_id = str(payload.get("job_id") or "").strip()
    if not job_id:
        raise ValueError("Missing job_id in Pub/Sub message")
    logger.info("Starting Sentinel job from Pub/Sub: %s", job_id)
    result = run_job(job_id, db=None)
    return result.model_dump()
