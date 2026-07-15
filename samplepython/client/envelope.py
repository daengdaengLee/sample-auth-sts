"""서버 /auth 가 받는 JSON 엔벨로프. 클라이언트가 SigV4 로 서명한 원본 GetCallerIdentity 요청을
재구성 없이 담아, 서버가 STS 로 위임할 수 있게 한다.

body 는 서명 대상 바이트를 정확히 보존하려고 base64(표준 인코딩)로 싣는다. 서버의 authRequest
스키마(method/url/headers/body)와 바이트 호환이다.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Envelope:
    """서버 /auth 로 보내는 JSON 엔벨로프."""

    method: str
    url: str
    headers: dict[str, list[str]]
    body: str  # base64 표준 인코딩

    def to_dict(self) -> dict[str, Any]:
        """JSON 직렬화용 dict 로 변환한다."""

        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
        }


def envelope_from_request(
    headers: dict[str, str],
    host: str,
    endpoint: str,
    body: bytes,
) -> Envelope:
    """헤더 기반 서명 요청을 엔벨로프로 직렬화한다. 서명된 요청 헤더를 그대로 옮기고, Host 를
    명시로 추가한다(SigV4 서명 범위에 host 가 들어가므로 STS 재검증이 살아 있으려면 함께 실어야
    한다). body 는 base64 표준 인코딩으로 싣는다.
    """

    out: dict[str, list[str]] = {name: [value] for name, value in headers.items()}
    out["Host"] = [host]
    return Envelope(
        method="POST",
        url=endpoint,
        headers=out,
        body=base64.standard_b64encode(body).decode("ascii"),
    )


def presigned_envelope(signed_url: str, host: str, binding_value: str) -> Envelope:
    """pre-signed URL 형태를 엔벨로프로 직렬화한다. SigV4 정보는 URL 쿼리에 있으므로 Authorization
    헤더가 없고, 서명 범위에 든 X-Server-Binding(실제 값)과 Host 만 헤더로 담는다. 본문은 빈 값이다.
    """

    return Envelope(
        method="GET",
        url=signed_url,
        headers={"X-Server-Binding": [binding_value], "Host": [host]},
        body="",
    )
