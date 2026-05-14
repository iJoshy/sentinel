"""Smoke tests for provider-agnostic Live Incident ingestion."""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path

from common.live_ingest import (
    decode_gcp_pubsub_push,
    ingest_live_records,
    normalize_gcp_logging_entries,
)
from common.store import SqliteDatabase


def _setup(db: SqliteDatabase) -> tuple[dict, dict, dict]:
    app = db.create_live_application(
        "paid_user",
        name="Fintech Switching Platform",
        environment="production",
    )
    service = db.create_live_service(
        app["id"],
        "paid_user",
        name="card-switch-service",
        service_type="api",
        criticality="high",
    )
    assert service is not None
    source = db.create_live_log_source(
        service["id"],
        "paid_user",
        provider="gcp_cloud_logging",
        source_ref='resource.labels.service_name="card-switch-service"',
        filter_query='severity>=ERROR OR textPayload:"timeout"',
    )
    assert source is not None
    return app, service, source


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db = SqliteDatabase(str(Path(tmp) / "sentinel.db"))
        try:
            app, service, source = _setup(db)
            result = ingest_live_records(
                db=db,
                clerk_user_id="paid_user",
                application_id=app["id"],
                service_id=service["id"],
                log_source_id=source["id"],
                provider="gcp_cloud_logging",
                records=[
                    {
                        "timestamp": "2026-05-14T10:00:00Z",
                        "message": "ERROR timeout contacting core banking adapter after 30s",
                        "severity": "ERROR",
                        "trace_id": "trace-1",
                        "labels": {"service_name": "card-switch-service"},
                        "payload": {"jsonPayload": {"message": "timeout"}},
                    }
                ],
            )
            assert result["accepted"] == 1, result
            assert len(result["signals"]) == 1, result
            assert result["signals"][0]["signal_type"] == "timeout_spike"

            repeat = ingest_live_records(
                db=db,
                clerk_user_id="paid_user",
                application_id=app["id"],
                service_id=service["id"],
                provider="gcp_cloud_logging",
                records=[
                    {
                        "message": "ERROR timeout contacting core banking adapter after 45s",
                        "severity": "ERROR",
                        "labels": {"service_name": "card-switch-service"},
                    }
                ],
            )
            assert repeat["accepted"] == 1, repeat
            signals = db.list_live_signals(app["id"], "paid_user")
            assert signals[0]["event_count"] >= 2

            gcp_entry = {
                "timestamp": "2026-05-14T10:01:00Z",
                "severity": "ERROR",
                "textPayload": "database connection refused in card switch",
                "resource": {"labels": {"service_name": "card-switch-service"}},
                "trace": "projects/demo/traces/abc",
            }
            encoded = base64.b64encode(json.dumps(gcp_entry).encode()).decode()
            entries = decode_gcp_pubsub_push({"message": {"data": encoded}})
            records = normalize_gcp_logging_entries(entries)
            assert records[0]["service_name"] == "card-switch-service"
            assert "database connection refused" in records[0]["message"]
        finally:
            db.close()

    print("Live Incident ingestion smoke test passed.")


if __name__ == "__main__":
    main()

