"""Async job enqueue helpers for cloud runtimes."""

from __future__ import annotations

import json
import logging
import os

from common.config import pubsub_jobs_topic

logger = logging.getLogger(__name__)


def enqueue_job(job_id: str) -> bool:
    """Publish a job id to the configured async backend.

    Returns ``False`` when no async queue is configured so callers can fall back
    to local/background execution.
    """

    topic = pubsub_jobs_topic()
    if topic:
        try:
            from google.cloud import pubsub_v1

            publisher = pubsub_v1.PublisherClient()
            payload = json.dumps({"job_id": job_id}).encode("utf-8")
            future = publisher.publish(topic, payload)
            future.result(timeout=10)
            logger.info("Published job_id=%s to Pub/Sub topic=%s", job_id, topic)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to publish job_id=%s to Pub/Sub: %s", job_id, exc)
            raise

    queue_url = os.getenv("SQS_QUEUE_URL", "").strip()
    if queue_url:
        try:
            import boto3

            client = boto3.client("sqs")
            client.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps({"job_id": job_id}),
            )
            logger.info("Published job_id=%s to SQS queue=%s", job_id, queue_url)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to publish job_id=%s to SQS: %s", job_id, exc)
            raise

    return False
