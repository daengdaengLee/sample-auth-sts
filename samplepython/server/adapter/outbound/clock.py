"""시계 어댑터. 도메인 Clock 포트를 시스템 시각으로 구현한다(신선도 판단용, 4단계)."""

from __future__ import annotations

from datetime import UTC, datetime

from server.domain.ports import Clock


class SystemClock:
    """time.now 를 한 곳에 가둔 Clock 구현. tz-aware UTC 를 돌려준다."""

    def now(self) -> datetime:
        return datetime.now(UTC)


def new() -> Clock:
    """SystemClock 을 만든다."""

    return SystemClock()


def _conforms(c: SystemClock) -> Clock:
    """컴파일타임 포트 준수 확인: SystemClock 이 Clock 을 만족하는지 mypy 가 검사한다."""

    return c
