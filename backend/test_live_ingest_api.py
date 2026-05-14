"""API smoke tests for Live Incident ingestion endpoints."""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

import api.auth as auth_mod
import api.main as api_main
from common.store import SqliteDatabase


def _seed(db_path: str, user_id: str = "dev_user") -> tuple[str, str, str]:
    db = SqliteDatabase(db_path)
    try:
        app = db.create_live_application(user_id, name="Fintech Switching Platform")
        service = db.create_live_service(
            app["id"],
            user_id,
            name="card-switch-service",
            criticality="high",
        )
        assert service is not None
        source = db.create_live_log_source(
            service["id"],
            user_id,
            provider="gcp_cloud_logging",
            source_ref='resource.labels.service_name="card-switch-service"',
        )
        assert source is not None
        return app["id"], service["id"], source["id"]
    finally:
        db.close()


def main() -> None:
    os.environ["AUTH_DISABLED"] = "true"
    os.environ["LIVE_INGEST_TOKEN"] = "test-live-token"
    original_entitlements = auth_mod.get_user_entitlements
    original_db = api_main._db

    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "sentinel.db")
        app_id, service_id, source_id = _seed(db_path)

        def _test_db():
            return SqliteDatabase(db_path)

        try:
            auth_mod.get_user_entitlements = lambda user: {
                "subscription_tier": "pro",
                "features": {"live_incident_board": True},
            }
            api_main._db = _test_db
            client = TestClient(api_main.app)

            normalized = client.post(
                "/api/live/ingest?run_analysis=false",
                json={
                    "application_id": app_id,
                    "service_id": service_id,
                    "log_source_id": source_id,
                    "provider": "gcp_cloud_logging",
                    "records": [
                        {
                            "message": "ERROR timeout contacting issuer adapter",
                            "severity": "ERROR",
                            "labels": {"service_name": "card-switch-service"},
                        }
                    ],
                },
            )
            assert normalized.status_code == 202, normalized.text
            assert normalized.json()["accepted"] == 1
            assert normalized.json()["signals"][0]["signal_type"] == "timeout_spike"

            blocked = client.post(
                "/api/live/ingest/gcp-pubsub?run_analysis=false",
                json={"application_id": app_id, "service_id": service_id, "message": {"data": "e30="}},
            )
            assert blocked.status_code == 403, blocked.text

            gcp_entry = {
                "timestamp": "2026-05-14T10:01:00Z",
                "severity": "ERROR",
                "textPayload": "database connection refused in switching API",
                "resource": {"labels": {"service_name": "card-switch-service"}},
            }
            encoded = base64.b64encode(json.dumps(gcp_entry).encode()).decode()
            pubsub = client.post(
                "/api/live/ingest/gcp-pubsub?run_analysis=false",
                headers={"X-Sentinel-Live-Token": "test-live-token"},
                json={
                    "application_id": app_id,
                    "log_source_id": source_id,
                    "message": {"data": encoded},
                },
            )
            assert pubsub.status_code == 202, pubsub.text
            assert pubsub.json()["accepted"] == 1
            assert pubsub.json()["signals"][0]["signal_type"] == "database_error"
        finally:
            auth_mod.get_user_entitlements = original_entitlements
            api_main._db = original_db

    print("Live Incident ingestion API smoke test passed.")


if __name__ == "__main__":
    main()
