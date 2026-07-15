"""서버와의 HTTP 전송(README "클라이언트 > 증명 생성 및 전송"의 5단계). 서명된 요청(엔벨로프)만
/auth 로 보내 발급 토큰을 받고, --verify 시 발급 토큰을 /verify 로 왕복 확인한다.
"""

from __future__ import annotations

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
    """서버가 비200 을 돌려줄 때의 에러. status/code/message 를 담는다."""

    def __init__(self, status: int, code: str, message: str) -> None:
        self.status = status
        self.code = code
        self.message = message
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
        return AuthResult(
            token=str(body["token"]),
            expires_at=_parse_rfc3339(str(body["expires_at"])),
        )

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
        """JSON POST 후 응답을 파싱한다. 비200 은 APIError 로 던진다."""

        resp = self._http.post(
            self._server_addr + path,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        content = resp.content[:_MAX_RESPONSE_BYTES]
        try:
            data = httpx.Response(resp.status_code, content=content).json()
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}

        if resp.status_code != 200:
            raise APIError(
                resp.status_code,
                str(data.get("error", "")),
                str(data.get("message", "")),
            )
        return data


def _parse_rfc3339(value: str) -> datetime:
    """RFC3339 문자열을 datetime 으로 파싱한다('Z' 접미사 포함)."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))
