"""Concise unit tests for shared pipeline helpers."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.pipeline import (
    _build_action_scorecard,
    _integration_notify_severities,
    parse_analysis,
)


def test_integration_notify_severities_defaults_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("INTEGRATION_NOTIFY_SEVERITIES", raising=False)
    assert _integration_notify_severities() == frozenset({"high", "critical"})


def test_integration_notify_severities_filters_invalid_values(monkeypatch) -> None:
    monkeypatch.setenv("INTEGRATION_NOTIFY_SEVERITIES", '"CRITICAL, medium,invalid"')
    assert _integration_notify_severities() == frozenset({"critical", "medium"})


def test_build_action_scorecard_matches_evidence_and_keeps_high_confidence() -> None:
    scorecard = _build_action_scorecard(
        action_text="Restart auth service pods",
        action_type="recommended",
        root_cause_summary="Auth service crash loop",
        root_confidence="high",
        evidence_pool=[
            "Auth service crash loop detected on pod auth-1",
            "Database latency is elevated",
        ],
    )
    assert scorecard["confidence"] == "high"
    assert scorecard["evidence"] == ["Auth service crash loop detected on pod auth-1"]


def test_build_action_scorecard_downgrades_high_confidence_for_checks() -> None:
    scorecard = _build_action_scorecard(
        action_text="Verify queue depth stabilizes",
        action_type="check",
        root_cause_summary="Queue backlog saturation",
        root_confidence="high",
        evidence_pool=[],
    )
    assert scorecard["confidence"] == "medium"
    assert scorecard["evidence"] == []


def test_parse_analysis_handles_valid_and_invalid_json() -> None:
    assert parse_analysis({"analysis_json": '{"status":"ok"}'}) == {"status": "ok"}
    assert parse_analysis({"analysis_json": "{not-json}"}) is None
    assert parse_analysis({}) is None
