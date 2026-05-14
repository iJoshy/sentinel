"""API smoke test for manual Live Incident correlation."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

import api.auth as auth_mod
import api.main as api_main
from common.live_ingest import ingest_live_records
from common.store import SqliteDatabase


def _seed(db_path: str, user_id: str = "dev_user") -> str:
    db = SqliteDatabase(db_path)
    try:
        app = db.create_live_application(user_id, name="Fintech Switching Platform")
        services = []
        for name in ("card-switch-service", "ledger-service"):
            service = db.create_live_service(app["id"], user_id, name=name, criticality="high")
            assert service is not None
            source = db.create_live_log_source(
                service["id"],
                user_id,
                provider="gcp_cloud_logging",
                source_ref=f'resource.labels.service_name="{name}"',
            )
            assert source is not None
            services.append((service, source))

        ingest_live_records(
            db=db,
            clerk_user_id=user_id,
            application_id=app["id"],
            service_id=services[0][0]["id"],
            log_source_id=services[0][1]["id"],
            provider="gcp_cloud_logging",
            correlate=False,
            records=[{"message": "ERROR timeout contacting issuer adapter", "severity": "ERROR"}],
        )
        ingest_live_records(
            db=db,
            clerk_user_id=user_id,
            application_id=app["id"],
            service_id=services[1][0]["id"],
            log_source_id=services[1][1]["id"],
            provider="gcp_cloud_logging",
            correlate=False,
            records=[{"message": "ERROR database connection refused in ledger", "severity": "ERROR"}],
        )
        return app["id"]
    finally:
        db.close()


def main() -> None:
    os.environ["AUTH_DISABLED"] = "true"
    original_entitlements = auth_mod.get_user_entitlements
    original_db = api_main._db

    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "sentinel.db")
        app_id = _seed(db_path)

        def _test_db():
            return SqliteDatabase(db_path)

        try:
            auth_mod.get_user_entitlements = lambda user: {
                "subscription_tier": "pro",
                "features": {"live_incident_board": True},
            }
            api_main._db = _test_db
            client = TestClient(api_main.app)
            response = client.post(f"/api/live/applications/{app_id}/correlate?run_analysis=false")
            assert response.status_code == 202, response.text
            payload = response.json()
            assert payload["status"] == "created", payload
            assert payload["service_count"] == 2
            assert payload["incident_id"]

            signals = client.get(f"/api/live/applications/{app_id}/signals")
            assert signals.status_code == 200, signals.text
            assert len(signals.json()["signals"]) == 2
        finally:
            auth_mod.get_user_entitlements = original_entitlements
            api_main._db = original_db

    print("Live Incident correlation API smoke test passed.")


if __name__ == "__main__":
    main()
