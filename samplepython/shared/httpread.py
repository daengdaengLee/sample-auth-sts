"""httpx 응답 본문을 상한까지만 읽는 공용 헬퍼. 서버 STS 어댑터와 클라이언트 전송 계층이
공유한다(둘 다 스트리밍으로 받아 읽기 자체를 상한으로 제한한다).

request() 로 받으면 httpx 가 본문 전체를 먼저 메모리에 올린 뒤라 사후 슬라이스로는 메모리
고갈을 못 막는다. 스트리밍 응답을 순회하며 누적이 상한을 넘는 순간 멈춰 실제 읽기를 상한 +
한 청크 이내로 묶는다(Go io.LimitReader 대응).
"""

from __future__ import annotations

import httpx


def read_capped(resp: httpx.Response, limit: int) -> tuple[bytes, bool]:
    """스트리밍 응답 본문을 최대 limit + 한 청크까지만 읽어 (body, oversized)를 돌려준다. 누적
    크기가 limit 을 넘는 순간 순회를 멈춰 실제 읽기를 제한한다(메모리 고갈 방지). oversized 는
    본문이 limit 을 초과했는지다(초과 시 body 는 그 시점까지의 바이트).
    """

    chunks: list[bytes] = []
    total = 0
    oversized = False
    for chunk in resp.iter_bytes():
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            oversized = True
            break
    return b"".join(chunks), oversized
