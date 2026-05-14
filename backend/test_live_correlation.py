"""Smoke tests for cross-service Live Incident correlation."""

from __future__ import annotations

import tempfile
from pathlib import Path

from common.live_correlation import correlate_application_signals
from common.live_ingest import ingest_live_records
from common.store import SqliteDatabase


def _source(db: SqliteDatabase, app_id: str, user_id: str, name: str, criticality: str = "high") -> tuple[dict, dict]:
    service = db.create_live_service(
        app_id,
        user_id,
        name=name,
        service_type="api",
        criticality=criticality,
    )
    assert service is not None
    source = db.create_live_log_source(
        service["id"],
        user_id,
        provider="gcp_cloud_logging",
        source_ref=f'resource.labels.service_name="{name}"',
    )
    assert source is not None
    return service, source


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db = SqliteDatabase(str(Path(tmp) / "sentinel.db"))
        try:
            user_id = "paid_user"
            app = db.create_live_application(user_id, name="Fintech Switching Platform")
            switch, switch_source = _source(db, app["id"], user_id, "card-switch-service", "critical")
            ledger, ledger_source = _source(db, app["id"], user_id, "ledger-service", "high")

            first = ingest_live_records(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                service_id=switch["id"],
                log_source_id=switch_source["id"],
                provider="gcp_cloud_logging",
                correlate=False,
                records=[
                    {
                        "message": "ERROR timeout contacting issuer adapter",
                        "severity": "ERROR",
                        "labels": {"service_name": "card-switch-service"},
                    }
                ],
            )
            assert first["accepted"] == 1
            no_incident = correlate_application_signals(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                run_analysis_async=False,
            )
            assert no_incident["status"] == "no_incident", no_incident

            second = ingest_live_records(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                service_id=ledger["id"],
                log_source_id=ledger_source["id"],
                provider="gcp_cloud_logging",
                correlate=False,
                records=[
                    {
                        "message": "ERROR database connection refused while writing ledger entry",
                        "severity": "ERROR",
                        "labels": {"service_name": "ledger-service"},
                    }
                ],
            )
            assert second["accepted"] == 1
            incident = correlate_application_signals(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                run_analysis_async=False,
            )
            assert incident["status"] == "created", incident
            assert incident["service_count"] == 2
            assert incident["incident_id"]
            assert incident["job_id"]

            rows = db.list_live_incidents(user_id, limit=10)
            assert len(rows) == 1
            assert rows[0]["source_log_groups_json"]

            updated = correlate_application_signals(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                run_analysis_async=False,
            )
            assert updated["status"] == "updated", updated
            assert updated["live_incident_id"] == incident["live_incident_id"]
        finally:
            db.close()

    with tempfile.TemporaryDirectory() as tmp:
        db = SqliteDatabase(str(Path(tmp) / "sentinel.db"))
        try:
            user_id = "paid_user"
            app = db.create_live_application(user_id, name="Critical Payments Platform")
            service, source = _source(db, app["id"], user_id, "settlement-worker", "critical")
            ingest_live_records(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                service_id=service["id"],
                log_source_id=source["id"],
                provider="gcp_cloud_logging",
                correlate=False,
                records=[
                    {
                        "message": "FATAL settlement-worker panic: service down",
                        "severity": "CRITICAL",
                        "labels": {"service_name": "settlement-worker"},
                    }
                ],
            )
            incident = correlate_application_signals(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                run_analysis_async=False,
            )
            assert incident["status"] == "created", incident
            assert incident["severity"] == "critical"
            assert incident["service_count"] == 1
        finally:
            db.close()

    print("Live Incident correlation smoke test passed.")


if __name__ == "__main__":
    main()

