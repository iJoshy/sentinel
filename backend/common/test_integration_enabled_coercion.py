"""Regression tests for integration `enabled` coercion (DB scalar → bool)."""

from __future__ import annotations

import pytest

from common.store import SqliteDatabase

_coerce = SqliteDatabase._coerce_integration_enabled


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, True),
        (True, True),
        (False, False),
        (0, False),
        (1, True),
        (-1, True),
        (0.0, False),
        (1.0, True),
        ("", False),
        ("0", False),
        ("1", True),
        ("false", False),
        ("FALSE", False),
        ("true", True),
        ("True", True),
        ("yes", True),
        ("no", False),
        ("on", True),
        ("off", False),
        ("  TRUE  ", True),
        ("  0  ", False),
        (b"0", False),
        (b"1", True),
        (b"false", False),
        (b"true", True),
        ("maybe", True),
        ("{}", True),
    ],
)
def test_coerce_integration_enabled_matrix(raw, expected: bool) -> None:
    assert _coerce(raw) is expected


def test_coerce_integration_enabled_invalid_utf8_bytes_defaults_true() -> None:
    assert _coerce(b"\xff\xfe") is True
