"""Shared pytest fixtures for backend test coverage."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


@pytest.fixture
def isolated_local_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Force all DB calls in a test to use an isolated local SQLite file."""
    db_path = tmp_path / "sentinel-test.db"
    monkeypatch.delenv("AURORA_CLUSTER_ARN", raising=False)
    monkeypatch.delenv("AURORA_SECRET_ARN", raising=False)
    monkeypatch.setenv("LOCAL_DB_PATH", str(db_path))
    return db_path


@pytest.fixture
def auth_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run API tests with local auth bypass."""
    monkeypatch.setenv("AUTH_DISABLED", "true")


@pytest.fixture(autouse=True)
def disable_llm_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent accidental calls to real model providers in unit tests."""
    monkeypatch.setenv("USE_BEDROCK", "false")
    monkeypatch.setenv("USE_OPEN_ROUTER", "false")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
