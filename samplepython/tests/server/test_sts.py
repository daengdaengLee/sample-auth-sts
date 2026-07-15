"""STS 신원 검증 어댑터 테스트(정규화/분류/위임)."""

from __future__ import annotations

import httpx
import pytest

from server.adapter.outbound import sts
from server.adapter.outbound.sts import VerificationError, _normalize_endpoint
from server.domain.types import PreservedRequest
from server.internal.config import StsSettings

_OK_XML = (
    b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    b"<GetCallerIdentityResult>"
    b"<Arn>arn:aws:iam::123456789012:role/workload</Arn>"
    b"<UserId>AIDAEXAMPLE</UserId>"
    b"<Account>123456789012</Account>"
    b"</GetCallerIdentityResult></GetCallerIdentityResponse>"
)

_ERR_XML = (
    b"<ErrorResponse><Error><Code>InvalidClientTokenId</Code>"
    b"<Message>bad signature</Message></Error></ErrorResponse>"
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://sts.amazonaws.com", "https://sts.amazonaws.com:443"),
        ("https://sts.amazonaws.com/", "https://sts.amazonaws.com:443"),
        ("https://sts.amazonaws.com.", "https://sts.amazonaws.com:443"),
        ("https://STS.amazonaws.com", "https://sts.amazonaws.com:443"),
        ("https://localhost:8443", "https://localhost:8443"),
        ("http://sts.amazonaws.com", ""),  # 비-https 는 무효
        ("not a url", ""),
    ],
)
def test_normalize_endpoint(raw: str, expected: str) -> None:
    assert _normalize_endpoint(raw) == expected


def _verifier(handler: httpx.MockTransport, allowed: list[str]) -> sts.Verifier:
    client = httpx.Client(transport=handler, follow_redirects=False)
    return sts.new(client, allowed)


def _preserved(url: str = "https://sts.amazonaws.com/") -> PreservedRequest:
    return PreservedRequest(
        method="POST", url=url, header={"Host": ["sts.amazonaws.com"]}, body=b"x"
    )


def test_verify_identity_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_OK_XML)

    v = _verifier(httpx.MockTransport(handler), ["https://sts.amazonaws.com"])
    identity = v.verify_identity(_preserved())
    assert identity.arn == "arn:aws:iam::123456789012:role/workload"
    assert identity.account == "123456789012"
    assert identity.user_id == "AIDAEXAMPLE"


def test_endpoint_not_in_allowlist_rejected_without_call() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=_OK_XML)

    v = _verifier(httpx.MockTransport(handler), ["https://sts.amazonaws.com"])
    with pytest.raises(VerificationError):
        v.verify_identity(_preserved(url="https://evil.example/"))
    assert not called  # HTTP 호출 없이 거부


def test_4xx_signature_rejection_is_verification_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=_ERR_XML)

    v = _verifier(httpx.MockTransport(handler), ["https://sts.amazonaws.com"])
    with pytest.raises(VerificationError) as ei:
        v.verify_identity(_preserved())
    assert ei.value.http_status == 403
    assert ei.value.sts_code == "InvalidClientTokenId"


def test_throttling_4xx_is_infra_error_not_verification() -> None:
    throttle = (
        b"<ErrorResponse><Error><Code>Throttling</Code>"
        b"<Message>rate exceeded</Message></Error></ErrorResponse>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, content=throttle)

    v = _verifier(httpx.MockTransport(handler), ["https://sts.amazonaws.com"])
    with pytest.raises(RuntimeError):  # 인프라 실패(재시도 대상), 무자격 아님
        v.verify_identity(_preserved())


def test_5xx_is_infra_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"oops")

    v = _verifier(httpx.MockTransport(handler), ["https://sts.amazonaws.com"])
    with pytest.raises(RuntimeError):
        v.verify_identity(_preserved())


def test_new_verifier_rejects_no_valid_endpoint() -> None:
    with pytest.raises(ValueError, match="유효한 https"):
        sts.new_verifier(httpx.Client(), StsSettings(endpoint_allowlist="http://plain, garbage"))
