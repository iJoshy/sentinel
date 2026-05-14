"""API smoke test for paid Live Incident topology setup endpoints."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

import api.auth as auth_mod
import api.main as api_main
from common.store import SqliteDatabase


def main() -> None:
    os.environ["AUTH_DISABLED"] = "true"
    original_entitlements = auth_mod.get_user_entitlements
    original_db = api_main._db

    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "sentinel.db")

        def _test_db():
            return SqliteDatabase(db_path)

        try:
            auth_mod.get_user_entitlements = lambda user: {
                "subscription_tier": "pro",
                "features": {"live_incident_board": True},
            }
            api_main._db = _test_db
            client = TestClient(api_main.app)

            app_resp = client.post(
                "/api/live/applications",
                json={
                    "name": "Fintech Switching Platform",
                    "environment": "production",
                    "description": "Payment authorization and settlement",
                },
            )
            assert app_resp.status_code == 201, app_resp.text
            app_id = app_resp.json()["application"]["id"]

            svc_resp = client.post(
                f"/api/live/applications/{app_id}/services",
                json={
                    "name": "card-switch-service",
                    "service_type": "api",
                    "criticality": "high",
                    "owner": "payments-platform",
                },
            )
            assert svc_resp.status_code == 201, svc_resp.text
            service_id = svc_resp.json()["service"]["id"]

            src_resp = client.post(
                f"/api/live/services/{service_id}/log-sources",
                json={
                    "provider": "gcp_cloud_logging",
                    "source_ref": 'resource.labels.service_name="card-switch-service"',
                    "filter_query": 'severity>=ERROR OR textPayload:"timeout"',
                },
            )
            assert src_resp.status_code == 201, src_resp.text

            list_resp = client.get("/api/live/applications")
            assert list_resp.status_code == 200, list_resp.text
            apps = list_resp.json()["applications"]
            assert len(apps) == 1
            assert len(apps[0]["services"]) == 1
            assert len(apps[0]["services"][0]["log_sources"]) == 1
        finally:
            auth_mod.get_user_entitlements = original_entitlements
            api_main._db = original_db

    print("Live Incident topology API smoke test passed.")


if __name__ == "__main__":
    main()

