"""Go time.ParseDuration 유사 파서.

설정값의 기간 표기("15m", "5m", "90s", "1h", "1h30m" 등)를 timedelta 로 바꾼다. Go 와 같은
표기를 그대로 받도록, 부호 있는 십진수 + 단위 접미사(ns, us/µs, ms, s, m, h)의 연속을 지원한다.
서버(설정)와 클라이언트(플래그)가 공유한다.
"""

from __future__ import annotations

import re
from datetime import timedelta

# 단위 -> 초. Go time.ParseDuration 이 지원하는 단위와 동일하다.
_UNIT_SECONDS: dict[str, float] = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "μs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}

# 숫자(소수 허용) + 단위 한 조각. Go 는 각 조각에 부호를 두지 않고 맨 앞에만 부호를 허용한다.
_SEGMENT = re.compile(r"(\d+(?:\.\d+)?|\.\d+)([a-zµμ]+)")


class DurationError(ValueError):
    """기간 문자열을 해석할 수 없을 때 던진다."""


def parse_duration(text: str) -> timedelta:
    """Go time.ParseDuration 형식 문자열을 timedelta 로 파싱한다. 해석할 수 없으면
    DurationError 를 던진다. "0" 은 0 으로 받는다(단위 없이 허용되는 유일한 값).
    """

    s = text.strip()
    if s == "":
        raise DurationError(f"빈 기간 문자열: {text!r}")

    sign = 1
    body = s
    if body[0] in "+-":
        if body[0] == "-":
            sign = -1
        body = body[1:]

    # Go 는 단위 없는 "0"(과 "+0"/"-0")만 예외적으로 허용한다.
    if body == "0":
        return timedelta(0)

    if body == "":
        raise DurationError(f"기간에 숫자가 없음: {text!r}")

    total_seconds = 0.0
    pos = 0
    matched_any = False
    while pos < len(body):
        m = _SEGMENT.match(body, pos)
        if m is None:
            raise DurationError(f"기간 형식이 올바르지 않음: {text!r}")
        number, unit = m.group(1), m.group(2)
        if unit not in _UNIT_SECONDS:
            raise DurationError(f"알 수 없는 기간 단위 {unit!r}: {text!r}")
        total_seconds += float(number) * _UNIT_SECONDS[unit]
        pos = m.end()
        matched_any = True

    if not matched_any:
        raise DurationError(f"기간 형식이 올바르지 않음: {text!r}")

    return timedelta(seconds=sign * total_seconds)
