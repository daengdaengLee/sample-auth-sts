"""클라이언트 transport(/auth, /verify 호출, APIError) 테스트."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from client.envelope import Envelope
from client.transport import APIError, Client


def _client(handler: httpx.MockTransport) -> Client:
    return Client("http://server.example/", httpx.Client(transport=handler))


def test_post_auth_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/auth"  # 후행 슬래시 제거 확인(//auth 아님)
        return httpx.Response(200, json={"token": "h.p.s", "expires_at": "2026-07-09T12:15:00Z"})

    result = _client(httpx.MockTransport(handler)).post_auth(
        Envelope(method="POST", url="x", headers={}, body="")
    )
    assert result.token == "h.p.s"
    assert result.expires_at == datetime(2026, 7, 9, 12, 15, 0, tzinfo=UTC)


def test_post_auth_api_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "binding_mismatch", "message": "거부됨"})

    with pytest.raises(APIError) as ei:
        _client(httpx.MockTransport(handler)).post_auth(
            Envelope(method="POST", url="x", headers={}, body="")
        )
    assert ei.value.status == 403
    assert ei.value.code == "binding_mismatch"


def test_post_auth_unparseable_expires_at_is_api_error() -> None:
    # 200 인데 expires_at 형식이 틀리면 ValueError 가 아니라 APIError 로 처리한다(status=None).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": "h.p.s", "expires_at": "not-a-date"})

    with pytest.raises(APIError) as ei:
        _client(httpx.MockTransport(handler)).post_auth(
            Envelope(method="POST", url="x", headers={}, body="")
        )
    assert ei.value.code == "invalid_response"
    assert ei.value.status is None


def test_oversized_response_is_api_error() -> None:
    # 상한(1 MiB)을 초과한 응답은 스트리밍 상한에서 잘려 response_too_large 로 거부된다.
    big = b'{"token":"' + b"A" * (1 << 21) + b'"}'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=big)

    with pytest.raises(APIError) as ei:
        _client(httpx.MockTransport(handler)).post_auth(
            Envelope(method="POST", url="x", headers={}, body="")
        )
    assert ei.value.code == "response_too_large"


def test_post_auth_missing_token_is_api_error() -> None:
    # 200 인데 token/expires_at 이 없으면 KeyError 가 아니라 APIError 로 처리한다.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    with pytest.raises(APIError) as ei:
        _client(httpx.MockTransport(handler)).post_auth(
            Envelope(method="POST", url="x", headers={}, body="")
        )
    assert ei.value.code == "invalid_response"


def test_post_verify_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/verify"
        return httpx.Response(
            200,
            json={
                "iss": "https://server.example",
                "sub": "arn:aws:iam::123456789012:role/workload",
                "aud": "https://server.example/clients",
                "exp": "2026-07-09T12:15:00Z",
                "iat": "2026-07-09T12:00:00Z",
                "jti": "abc",
                "account": "123456789012",
                "user_id": "AIDAEXAMPLE",
            },
        )

    claims = _client(httpx.MockTransport(handler)).post_verify("h.p.s")
    assert claims.subject == "arn:aws:iam::123456789012:role/workload"
    assert claims.account == "123456789012"


def test_post_verify_api_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_token", "message": "무효"})

    with pytest.raises(APIError) as ei:
        _client(httpx.MockTransport(handler)).post_verify("bad")
    assert ei.value.status == 401
    assert ei.value.code == "invalid_token"
