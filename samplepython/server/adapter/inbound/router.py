"""수신 어댑터의 라우터. FastAPI 앱을 만들어 HTTP 전송 계층을 담당하고, 요청을 도메인 코어의
유스케이스로 넘긴다. 신뢰 판단 로직은 담지 않는다.

/healthz, /auth, /verify 를 등록한다. /auth 는 파싱한 서명 요청을, /verify 는 파싱한 토큰을 각각
인바운드 포트로 넘긴다. 본문을 읽는 부분만 async 로 두고(413 상한 -> JSON 파싱), 이후 파싱/판단/
STS 위임 같은 블로킹 처리는 스레드풀에서 실행해 이벤트 루프를 막지 않는다(도메인 코어는 동기).
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from server.adapter.inbound.auth import AuthHandler
from server.adapter.inbound.http_util import MAX_BODY_BYTES, ClientError, read_json_capped
from server.adapter.inbound.middleware import access_middleware
from server.adapter.inbound.verify import VerifyHandler
from server.domain.ports import Authenticator, TokenVerifier


def create_app(
    logger: logging.Logger,
    auth: Authenticator | None,
    verify: TokenVerifier | None,
) -> FastAPI:
    """요청 로거/미들웨어와 서버가 노출하는 라우트를 등록한 FastAPI 앱을 만든다. auth/verify 는
    조립 지점에서 주입하는 인바운드 포트다.

    두 인바운드 포트는 필수다: None 은 오설정이 아니라 프로그래머 배선 버그이므로 조립 시점에
    즉시 예외로 드러낸다(오설정을 예외로 돌려주는 config load/new_verifier 와는 다른 부류).
    """

    if auth is None:
        raise ValueError("create_app: auth(Authenticator) 가 None 임")
    if verify is None:
        raise ValueError("create_app: verify(TokenVerifier) 가 None 임")

    auth_handler = AuthHandler(auth)
    verify_handler = VerifyHandler(verify)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    # request_id 부여 + 접근 로깅. 이후 이 요청 흐름의 모든 로그에 request_id 가 붙는다.
    app.middleware("http")(access_middleware(logger))

    @app.get("/healthz")
    async def health() -> JSONResponse:
        """운영용 헬스체크 응답."""

        return JSONResponse(status_code=200, content={"status": "ok"})

    @app.post("/auth")
    async def authenticate(request: Request) -> Response:
        try:
            payload = await read_json_capped(request, MAX_BODY_BYTES)
        except ClientError as e:
            return e.response()
        status, body = await run_in_threadpool(auth_handler.handle, payload)
        return JSONResponse(status_code=status, content=body)

    @app.post("/verify")
    async def verify_token(request: Request) -> Response:
        try:
            payload = await read_json_capped(request, MAX_BODY_BYTES)
        except ClientError as e:
            return e.response()
        status, body = await run_in_threadpool(verify_handler.handle, payload)
        return JSONResponse(status_code=status, content=body)

    return app
