"""수신 어댑터의 공용 HTTP 헬퍼: 본문 상한 검사(413) -> JSON 파싱(400) 순서와 에러 응답.

Go 의 MaxBytesReader -> ShouldBindJSON 순서(상한 -> 파싱, 413이 400보다 앞)를 정확히 재현한다.
/auth 와 /verify 가 공유한다.
"""

from __future__ import annotations

import json
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

# 수신 어댑터가 받는 JSON 요청 본문의 최대 바이트(/auth 서명 엔벨로프, /verify 토큰 모두
# 작으므로 넉넉히 1 MiB). 넘으면 413 으로 거부한다. 상한이 없으면 거대한 본문으로 메모리를
# 고갈시키는 값싼 DoS 가 가능하다.
MAX_BODY_BYTES = 1 << 20


class ClientError(Exception):
    """수신 어댑터가 도메인 호출 전에 요청을 거부할 때 쓰는 내부 예외. status/code/message 를
    담아 상위에서 JSON 에러 응답으로 변환한다.
    """

    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")

    def response(self) -> JSONResponse:
        return error_response(self.status, self.code, self.message)


def error_response(status: int, code: str, message: str) -> JSONResponse:
    """실패 응답을 JSON({error, message})으로 쓴다."""

    return JSONResponse(status_code=status, content={"error": code, "message": message})


async def read_json_capped(request: Request, limit: int) -> Any:
    """요청 본문을 limit 바이트로 제한해 읽은 뒤 JSON 으로 파싱해 돌려준다. 상한 초과는 413
    body_too_large, 그 외 파싱 실패는 400 invalid_body 로 ClientError 를 던진다(호출부가 응답으로
    변환). 상한을 먼저 검사한 뒤 파싱하므로 413이 400보다 앞선다.
    """

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise ClientError(413, "body_too_large", "요청 본문이 허용 크기를 초과함")
        chunks.append(chunk)

    raw = b"".join(chunks)
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ClientError(400, "invalid_body", "요청 본문 JSON 파싱 실패") from e
