"""GCP runtime adapter tests."""

from __future__ import annotations

import base64
import json
import sys
import types
from unittest.mock import MagicMock, patch

import pytest


def test_active_model_prefers_vertex_ai(monkeypatch: pytest.MonkeyPatch) -> None:
    from common.config import active_model

    monkeypatch.setenv("USE_VERTEX_AI", "true")
    monkeypatch.setenv("VERTEX_AI_MODEL", "gemini-2.5-flash")

    assert active_model() == "gemini-2.5-flash"


def test_get_database_uses_postgres_when_gcp_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import common.store as store

    class _FakePostgres:
        pass

    monkeypatch.delenv("AURORA_CLUSTER_ARN", raising=False)
    monkeypatch.delenv("AURORA_SECRET_ARN", raising=False)
    monkeypatch.setenv("GCP_CLOUDSQL_CONNECTION_NAME", "project:us-central1:sentinel")
    monkeypatch.setattr(store, "PostgresDatabase", _FakePostgres)

    assert isinstance(store.get_database(), _FakePostgres)


def test_enqueue_job_publishes_to_pubsub(monkeypatch: pytest.MonkeyPatch) -> None:
    from common.queue import enqueue_job

    published: dict[str, object] = {}

    class _Future:
        def result(self, timeout: int) -> None:
            published["timeout"] = timeout

    class _Publisher:
        def publish(self, topic: str, payload: bytes):
            published["topic"] = topic
            published["payload"] = json.loads(payload.decode("utf-8"))
            return _Future()

    pubsub_mod = types.SimpleNamespace(PublisherClient=lambda: _Publisher())
    cloud_mod = types.ModuleType("google.cloud")
    cloud_mod.pubsub_v1 = pubsub_mod
    google_mod = types.ModuleType("google")
    google_mod.cloud = cloud_mod

    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.pubsub_v1", pubsub_mod)
    monkeypatch.setenv("PUBSUB_JOBS_TOPIC", "projects/p/topics/sentinel-jobs")

    assert enqueue_job("job-123") is True
    assert published["topic"] == "projects/p/topics/sentinel-jobs"
    assert published["payload"] == {"job_id": "job-123"}


def test_gcp_function_decodes_pubsub_and_runs_job() -> None:
    from gcp_function import pubsub_run_job

    payload = base64.b64encode(json.dumps({"job_id": "job-123"}).encode()).decode()
    event = {"message": {"data": payload}}

    with patch("gcp_function.run_job") as run_job:
        run_job.return_value = MagicMock(model_dump=lambda: {"status": "completed"})
        assert pubsub_run_job(event) == {"status": "completed"}
        run_job.assert_called_once_with("job-123", db=None)


def test_sendgrid_email_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from common.email import send_follow_up_reminder

    monkeypatch.setenv("SENDGRID_API_KEY", "sg_test")
    monkeypatch.setenv("SENDGRID_FROM", "Sentinel <ops@example.com>")

    with patch("common.email.httpx.post") as post:
        response = MagicMock()
        response.raise_for_status = MagicMock()
        post.return_value = response

        assert send_follow_up_reminder(
            "user@example.com", "Check database pool", "2026-05-05T10:00:00Z"
        )

    _, kwargs = post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer sg_test"
    assert kwargs["json"]["from"] == {"email": "ops@example.com", "name": "Sentinel"}
    assert kwargs["json"]["personalizations"][0]["to"][0]["email"] == "user@example.com"


def test_pushover_dispatch_uses_env_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    from integrations.dispatcher import _post_pushover, synthetic_test_analysis

    monkeypatch.setenv("PUSHOVER_TOKEN", "app-token")
    monkeypatch.setenv("PUSHOVER_USER_KEY", "user-key")

    with patch("integrations.dispatcher.httpx.Client") as client_cls:
        client = client_cls.return_value.__enter__.return_value
        response = MagicMock()
        response.raise_for_status = MagicMock()
        client.post.return_value = response

        _post_pushover({}, synthetic_test_analysis(), incident_title="Checkout outage")

    client.post.assert_called_once()
    url, = client.post.call_args.args
    assert url == "https://api.pushover.net/1/messages.json"
    assert client.post.call_args.kwargs["data"]["token"] == "app-token"
    assert client.post.call_args.kwargs["data"]["user"] == "user-key"
