"""수신 어댑터 미들웨어. 요청마다 request_id 를 만들어(또는 헤더에서 이어받아) 로깅 컨텍스트와
응답 헤더에 실어주고, 요청당 한 줄 접근 로그를 남긴다.

Go 의 RequestID -> requestLogger 미들웨어 순서를 한 미들웨어로 합쳐 순서를 보장한다. 이후 이
요청 흐름에서 남기는 모든 로그에 request_id 가 자동으로 붙는다(logging.append_ctx).
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import Response

from server.internal.logging import append_ctx

# 요청 ID 를 주고받는 헤더 이름. 들어온 값이 있으면 이어받아 호출 경계를 넘어 상관관계를 유지한다.
_REQUEST_ID_HEADER = "X-Request-Id"

# 이어받는 request_id 의 최대 길이. 클라이언트가 준 값을 그대로 로그/응답에 반영하므로, 로그
# 비대화를 막기 위해 상한을 둔다.
_MAX_REQUEST_ID_LEN = 128

# 이어받아도 안전한 문자셋(hex/UUID 형식 수용).
_ALLOWED_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _is_valid_request_id(value: str) -> bool:
    """이어받아도 안전한 request_id 인지 검사한다. 길이 1..128, 문자셋 [A-Za-z0-9_-] 만 허용한다.
    이 범위를 벗어난 값은 로그/응답 헤더에 그대로 싣기에 위험하므로 거부한다.
    """

    if len(value) == 0 or len(value) > _MAX_REQUEST_ID_LEN:
        return False
    return all(ch in _ALLOWED_ID_CHARS for ch in value)


def _new_request_id() -> str:
    """16바이트 난수를 hex 로 인코딩한 요청 ID 를 만든다."""

    return secrets.token_hex(16)


def access_middleware(
    logger: logging.Logger,
) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    """request_id 부여 + 접근 로깅을 수행하는 http 미들웨어를 만든다."""

    async def middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        incoming = request.headers.get(_REQUEST_ID_HEADER, "")
        request_id = incoming if _is_valid_request_id(incoming) else _new_request_id()

        # 이후 이 요청 흐름의 모든 로그(logger.info 등)에 request_id 가 자동으로 붙는다.
        append_ctx(request_id=request_id)

        start = time.monotonic()
        response = await call_next(request)
        latency_ms = (time.monotonic() - start) * 1000.0

        response.headers[_REQUEST_ID_HEADER] = request_id

        client_ip = request.client.host if request.client is not None else ""
        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "latency_ms": round(latency_ms, 3),
                "client_ip": client_ip,
            },
        )
        return response

    return middleware
