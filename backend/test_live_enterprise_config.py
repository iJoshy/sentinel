"""Smoke test for enterprise Live Incident application topology config."""

from __future__ import annotations

import tempfile
from pathlib import Path

from common.store import SqliteDatabase


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db = SqliteDatabase(str(Path(tmp) / "sentinel.db"))
        try:
            app = db.create_live_application(
                "paid_user",
                name="Fintech Switching Platform",
                environment="production",
                description="Payment authorization and settlement",
            )
            assert app["name"] == "Fintech Switching Platform"

            service = db.create_live_service(
                app["id"],
                "paid_user",
                name="card-switch-service",
                service_type="api",
                criticality="high",
                owner="payments-platform",
                dependency_order=1,
            )
            assert service is not None
            assert service["criticality"] == "high"

            source = db.create_live_log_source(
                service["id"],
                "paid_user",
                provider="gcp_cloud_logging",
                source_ref='resource.labels.service_name="card-switch-service"',
                filter_query='severity>=ERROR OR textPayload:"timeout"',
            )
            assert source is not None
            assert source["provider"] == "gcp_cloud_logging"

            apps = db.list_live_applications("paid_user")
            assert len(apps) == 1
            assert len(apps[0]["services"]) == 1
            assert len(apps[0]["services"][0]["log_sources"]) == 1

            other_user_apps = db.list_live_applications("free_user")
            assert other_user_apps == []
        finally:
            db.close()

    print("Enterprise Live Incident config smoke test passed.")


if __name__ == "__main__":
    main()

