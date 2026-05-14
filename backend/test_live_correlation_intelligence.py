"""Tests for richer Live Incident source correlation intelligence."""

from __future__ import annotations

import tempfile
from pathlib import Path

from common.live_correlation import correlate_application_signals
from common.live_ingest import ingest_live_records, normalize_gcp_logging_entries
from common.store import SqliteDatabase


def _service(
    db: SqliteDatabase,
    app_id: str,
    user_id: str,
    *,
    name: str,
    dependency_order: int,
    criticality: str = "high",
) -> tuple[dict, dict]:
    service = db.create_live_service(
        app_id,
        user_id,
        name=name,
        service_type="api",
        criticality=criticality,
        dependency_order=dependency_order,
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


def test_shared_trace_and_dependency_order_select_upstream_source() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db = SqliteDatabase(str(Path(tmp) / "sentinel.db"))
        try:
            user_id = "paid_user"
            app = db.create_live_application(user_id, name="Switching Platform")
            gateway, gateway_source = _service(
                db,
                app["id"],
                user_id,
                name="api-gateway",
                dependency_order=0,
                criticality="critical",
            )
            ledger, ledger_source = _service(
                db,
                app["id"],
                user_id,
                name="ledger-service",
                dependency_order=4,
            )

            ingest_live_records(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                service_id=gateway["id"],
                log_source_id=gateway_source["id"],
                provider="gcp_cloud_logging",
                correlate=False,
                records=[
                    {
                        "timestamp": "2026-05-14T10:00:01Z",
                        "message": "ERROR timeout waiting for issuer route",
                        "severity": "ERROR",
                        "trace_id": "trace-shared-1",
                        "request_id": "req-100",
                        "labels": {"service_name": "api-gateway"},
                    }
                ],
            )
            for offset in range(3):
                ingest_live_records(
                    db=db,
                    clerk_user_id=user_id,
                    application_id=app["id"],
                    service_id=ledger["id"],
                    log_source_id=ledger_source["id"],
                    provider="gcp_cloud_logging",
                    correlate=False,
                    records=[
                        {
                            "timestamp": f"2026-05-14T10:00:0{offset + 3}Z",
                            "message": f"ERROR database connection refused while writing ledger entry {offset}",
                            "severity": "ERROR",
                            "trace_id": "trace-shared-1",
                            "request_id": "req-100",
                            "labels": {"service_name": "ledger-service"},
                        }
                    ],
                )

            result = correlate_application_signals(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                run_analysis_async=False,
            )
            assert result["status"] == "created", result
            assert result["source_candidates"][0]["service_name"] == "api-gateway", result
            assert "shared trace" in result["source_reason"], result
            assert "earliest service" in result["source_reason"], result
        finally:
            db.close()


def test_deployment_version_and_window_select_changed_service() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db = SqliteDatabase(str(Path(tmp) / "sentinel.db"))
        try:
            user_id = "paid_user"
            app = db.create_live_application(user_id, name="Payments Platform")
            gateway, gateway_source = _service(
                db,
                app["id"],
                user_id,
                name="api-gateway",
                dependency_order=0,
                criticality="high",
            )
            pricing, pricing_source = _service(
                db,
                app["id"],
                user_id,
                name="pricing-service",
                dependency_order=2,
                criticality="high",
            )

            ingest_live_records(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                service_id=pricing["id"],
                log_source_id=pricing_source["id"],
                provider="gcp_cloud_logging",
                correlate=False,
                records=[
                    {
                        "timestamp": "2026-05-14T11:05:00Z",
                        "message": "Unhandled exception loading pricing rules",
                        "severity": "ERROR",
                        "deployment_version": "pricing-2026-05-14.1",
                        "labels": {"service_name": "pricing-service"},
                    }
                ],
            )
            ingest_live_records(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                service_id=gateway["id"],
                log_source_id=gateway_source["id"],
                provider="gcp_cloud_logging",
                correlate=False,
                records=[
                    {
                        "timestamp": "2026-05-14T11:05:12Z",
                        "message": "ERROR upstream failure while quoting transaction",
                        "severity": "ERROR",
                        "labels": {"service_name": "api-gateway"},
                    }
                ],
            )

            result = correlate_application_signals(
                db=db,
                clerk_user_id=user_id,
                application_id=app["id"],
                run_analysis_async=False,
            )
            assert result["status"] == "created", result
            assert result["source_candidates"][0]["service_name"] == "pricing-service", result
            assert "deployment version present" in result["source_reason"], result
        finally:
            db.close()


def test_gcp_normalization_extracts_request_and_deployment_metadata() -> None:
    records = normalize_gcp_logging_entries(
        [
            {
                "timestamp": "2026-05-14T12:00:00Z",
                "severity": "ERROR",
                "jsonPayload": {
                    "message": "timeout talking to acquirer",
                    "requestId": "req-normalized",
                    "version": "switch-v7",
                },
                "resource": {"labels": {"service_name": "switch-service", "revision_name": "switch-v7"}},
                "trace": "projects/demo/traces/trace-normalized",
            }
        ]
    )
    assert records[0]["request_id"] == "req-normalized"
    assert records[0]["deployment_version"] == "switch-v7"
    assert records[0]["labels"]["deployment_version"] == "switch-v7"


def main() -> None:
    test_shared_trace_and_dependency_order_select_upstream_source()
    test_deployment_version_and_window_select_changed_service()
    test_gcp_normalization_extracts_request_and_deployment_metadata()
    print("Live Incident correlation intelligence tests passed.")


if __name__ == "__main__":
    main()
