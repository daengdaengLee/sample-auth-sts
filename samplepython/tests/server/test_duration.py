"""Go time.ParseDuration 유사 파서 테스트."""

from __future__ import annotations

from datetime import timedelta

import pytest

from server.internal.duration import DurationError, parse_duration


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("15m", timedelta(minutes=15)),
        ("5m", timedelta(minutes=5)),
        ("90s", timedelta(seconds=90)),
        ("1h", timedelta(hours=1)),
        ("1h30m", timedelta(hours=1, minutes=30)),
        ("500ms", timedelta(milliseconds=500)),
        ("0", timedelta(0)),
        ("2h45m30s", timedelta(hours=2, minutes=45, seconds=30)),
        ("-5m", timedelta(minutes=-5)),
    ],
)
def test_valid(text: str, expected: timedelta) -> None:
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "notaduration", "15", "15x", "m", "abc"])
def test_invalid(text: str) -> None:
    with pytest.raises(DurationError):
        parse_duration(text)
