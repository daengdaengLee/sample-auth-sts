"""shared.httpread.read_capped 직접 단위 테스트."""

from __future__ import annotations

import httpx
import pytest

from shared.httpread import read_capped

_LIMIT = 1 << 20  # 1 MiB


@pytest.mark.parametrize(
    ("size", "oversized"),
    [
        (0, False),  # 빈 본문
        (10, False),  # 상한 이하
        (_LIMIT, False),  # 정확히 상한
        (_LIMIT + 1, True),  # 상한 초과
        (_LIMIT * 2, True),  # 크게 초과
    ],
)
def test_read_capped_boundary(size: int, oversized: bool) -> None:
    content = b"A" * size
    resp = httpx.Response(200, content=content)
    body, got_oversized = read_capped(resp, _LIMIT)
    assert got_oversized is oversized
    if not oversized:
        # 상한 이하면 본문을 그대로 돌려준다.
        assert body == content
    else:
        # 초과면 조기 종료로 상한을 넘긴 바이트까지만 읽는다(전체 크기보다 작을 수 있음).
        assert len(body) <= size
        assert len(body) > _LIMIT
