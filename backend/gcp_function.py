"""Google Cloud Function entrypoints for Sentinel."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from common.pipeline import run_job

logger = logging.getLogger(__name__)


def _decode_pubsub_payload(event: Any) -> dict[str, Any]:
    data = getattr(event, "data", None) or event or {}
    message = data.get("message") or {}
    raw = message.get("data") or data.get("data") or ""
    if not raw:
        return {}
    decoded = base64.b64decode(raw).decode("utf-8")
    return json.loads(decoded)


def pubsub_run_job(event: Any, context: Any | None = None) -> dict[str, Any]:
    """Run one analysis job from Pub/Sub.

    Cloud Functions Gen2 may invoke this entrypoint with a CloudEvent-shaped
    object or with the older ``(data, context)`` background-event signature,
    depending on the Functions Framework trigger mode.
    """

    del context
    payload = _decode_pubsub_payload(event)
    job_id = str(payload.get("job_id") or "").strip()
    if not job_id:
        raise ValueError("Missing job_id in Pub/Sub message")
    logger.info("Starting Sentinel job from Pub/Sub: %s", job_id)
    result = run_job(job_id, db=None)
    return result.model_dump()
