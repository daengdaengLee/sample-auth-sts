"""서버와의 HTTP 전송(README "클라이언트 > 증명 생성 및 전송"의 5단계). 서명된 요청(엔벨로프)만
/auth 로 보내 발급 토큰을 받고, --verify 시 발급 토큰을 /verify 로 왕복 확인한다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

import httpx

from client.envelope import Envelope

# 응답 본문을 읽을 최대 바이트(1 MiB). 서버 응답은 작으므로 넉넉히 둔다.
_MAX_RESPONSE_BYTES = 1 << 20


@dataclass(frozen=True)
class AuthResult:
    """/auth 성공 응답. 발급 토큰과 만료 시각."""

    token: str
    expires_at: datetime


@dataclass(frozen=True)
class Claims:
    """/verify 가 돌려준 토큰 클레임."""

    issuer: str
    subject: str
    audience: str
    expires_at: str
    issued_at: str
    jti: str
    account: str
    user_id: str


class APIError(Exception):
    """서버 응답 처리 실패. 실제 HTTP 비200 응답은 정수 status 를, 형식이 어긋난 응답(200 인데
    필드 누락/형식 오류, 과대 응답 등 합성 오류)은 status=None 을 담아, 성공 코드를 오류로
    표기하는 오해를 피한다.
    """

    def __init__(self, status: int | None, code: str, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message
        if status is None:
            super().__init__(f"서버 응답 오류(error={code}): {message}")
        else:
            super().__init__(f"서버 오류(status={status} error={code}): {message}")


class Client:
    """서버 /auth, /verify 를 호출하는 클라이언트."""

    def __init__(self, server_addr: str, http_client: httpx.Client) -> None:
        # 후행 슬래시를 제거해 //auth 같은 경로(리다이렉트/404)를 피한다.
        self._server_addr = server_addr.rstrip("/")
        self._http = http_client

    def post_auth(self, envelope: Envelope) -> AuthResult:
        """엔벨로프를 /auth 로 POST 해 발급 토큰을 받는다."""

        body = self._post_json("/auth", envelope.to_dict())
        # 200 인데 필드가 없거나 형식이 틀리면 KeyError/ValueError 대신 명확한 에러로 처리한다
        # (형식 어긋난 응답 방어). status=None 으로 던져 "status=200 오류" 오해를 피한다.
        token = body.get("token")
        expires_at = body.get("expires_at")
        if not isinstance(token, str) or not isinstance(expires_at, str):
            raise APIError(None, "invalid_response", "서버 응답에 token/expires_at 이 없음")
        try:
            parsed_expires = _parse_rfc3339(expires_at)
        except ValueError as e:
            raise APIError(None, "invalid_response", "서버 응답 expires_at 형식 오류") from e
        return AuthResult(token=token, expires_at=parsed_expires)

    def post_verify(self, token: str) -> Claims:
        """토큰을 /verify 로 POST 해 클레임을 받는다."""

        body = self._post_json("/verify", {"token": token})
        return Claims(
            issuer=str(body.get("iss", "")),
            subject=str(body.get("sub", "")),
            audience=str(body.get("aud", "")),
            expires_at=str(body.get("exp", "")),
            issued_at=str(body.get("iat", "")),
            jti=str(body.get("jti", "")),
            account=str(body.get("account", "")),
            user_id=str(body.get("user_id", "")),
        )

    def _post_json(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        """JSON POST 후 응답을 파싱한다. 비200 은 APIError 로 던진다.

        스트리밍으로 받아 본문 읽기 자체를 상한으로 제한한다(서버 STS 어댑터의 _read_capped 와
        동일 취지). post() 로 받으면 httpx 가 본문 전체를 먼저 메모리에 올린 뒤라 사후 슬라이스로는
        상한이 무력하다.
        """

        with self._http.stream(
            "POST",
            self._server_addr + path,
            json=payload,
            headers={"Content-Type": "application/json"},
        ) as resp:
            status = resp.status_code
            content, oversized = _read_capped(resp)

        if oversized:
            raise APIError(None, "response_too_large", "서버 응답이 허용 크기를 초과함")

        try:
            parsed = json.loads(content)
        except ValueError:
            parsed = None
        data: dict[str, object] = parsed if isinstance(parsed, dict) else {}

        if status != 200:
            raise APIError(
                status,
                str(data.get("error", "")),
                str(data.get("message", "")),
            )
        return data


def _read_capped(resp: httpx.Response) -> tuple[bytes, bool]:
    """스트리밍 응답 본문을 최대 상한 + 한 청크까지만 읽어 (body, oversized)를 돌려준다. 누적
    크기가 상한을 넘는 순간 순회를 멈춰 실제 읽기를 제한한다(메모리 고갈 방지).
    """

    chunks: list[bytes] = []
    total = 0
    oversized = False
    for chunk in resp.iter_bytes():
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            oversized = True
            break
    return b"".join(chunks), oversized


def _parse_rfc3339(value: str) -> datetime:
    """RFC3339 문자열을 datetime 으로 파싱한다('Z' 접미사 포함)."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))
