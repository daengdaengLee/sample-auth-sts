"""/auth 수신 어댑터 테스트(엔벨로프 파싱/형태 판별/에러 매핑)."""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from server.adapter.inbound.router import create_app
from server.domain.errors import RejectionReason, VerificationRejected, reject
from server.domain.types import (
    AuthenticateInput,
    AuthenticateOutput,
    Credential,
    Identity,
    VerifyTokenInput,
    VerifyTokenOutput,
)


class _FakeAuth:
    def __init__(self, error: Exception | None = None) -> None:
        self._error = error
        self.called = False
        self.got: AuthenticateInput | None = None

    def authenticate(self, in_: AuthenticateInput) -> AuthenticateOutput:
        self.called = True
        self.got = in_
        if self._error is not None:
            raise self._error
        return AuthenticateOutput(
            credential=Credential(
                token="h.p.s", expires_at=datetime(2026, 7, 9, 12, 15, tzinfo=UTC)
            ),
            identity=Identity(arn="arn:aws:iam::123456789012:role/workload"),
        )


class _FakeVerify:
    def verify_token(self, in_: VerifyTokenInput) -> VerifyTokenOutput:  # pragma: no cover
        raise AssertionError("verify 는 이 테스트에서 호출되지 않음")


def _client(auth: _FakeAuth) -> TestClient:
    return TestClient(create_app(logging.getLogger("t"), auth, _FakeVerify()))


def _valid_envelope() -> dict[str, Any]:
    return {
        "method": "POST",
        "url": "https://sts.amazonaws.com/",
        "headers": {
            "Authorization": [
                "AWS4-HMAC-SHA256 Credential=AKID/20260709/us-east-1/sts/aws4_request, "
                "SignedHeaders=host;x-amz-date;x-server-binding, Signature=deadbeef"
            ],
            "X-Amz-Date": ["20260709T120000Z"],
            "X-Server-Binding": ["https://server.example/audience"],
            "Host": ["sts.amazonaws.com"],
            "Content-Type": ["application/x-www-form-urlencoded"],
        },
        "body": base64.standard_b64encode(b"Action=GetCallerIdentity&Version=2011-06-15").decode(),
    }


def test_valid_header_envelope_ok() -> None:
    auth = _FakeAuth()
    r = _client(auth).post("/auth", json=_valid_envelope())
    assert r.status_code == 200
    assert r.json()["token"] == "h.p.s"
    assert r.json()["expires_at"] == "2026-07-09T12:15:00Z"
    assert auth.called
    # 코어로 넘어간 값이 헤더 폼으로 파싱됐는지 확인.
    assert auth.got is not None
    assert auth.got.request.binding_value == "https://server.example/audience"
    assert auth.got.request.action == "GetCallerIdentity"


def test_body_too_large_413() -> None:
    auth = _FakeAuth()
    big = {"method": "POST", "url": "x", "headers": {}, "body": "A" * (1 << 21)}
    r = _client(auth).post("/auth", json=big)
    assert r.status_code == 413
    assert r.json()["error"] == "body_too_large"
    assert not auth.called


def test_invalid_json_400() -> None:
    r = _client(_FakeAuth()).post(
        "/auth", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_body"


def test_bad_base64_body_400() -> None:
    env = _valid_envelope()
    env["body"] = "!!!not base64!!!"
    r = _client(_FakeAuth()).post("/auth", json=env)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_body"


def test_binding_not_signed_403() -> None:
    env = _valid_envelope()
    # SignedHeaders 에서 x-server-binding 을 뺀다 -> 바인딩이 서명 범위 밖.
    env["headers"]["Authorization"] = [
        "AWS4-HMAC-SHA256 Credential=AKID/x, SignedHeaders=host;x-amz-date, Signature=deadbeef"
    ]
    r = _client(_FakeAuth()).post("/auth", json=env)
    assert r.status_code == 403
    assert r.json()["error"] == "binding_not_signed"


def test_amz_date_not_signed_400() -> None:
    env = _valid_envelope()
    env["headers"]["Authorization"] = [
        "AWS4-HMAC-SHA256 Credential=AKID/x, "
        "SignedHeaders=host;x-server-binding, Signature=deadbeef"
    ]
    r = _client(_FakeAuth()).post("/auth", json=env)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_signature"


def test_form_undeterminable_400() -> None:
    # Authorization 도 없고 presigned 쿼리(X-Amz-Algorithm)도 없음.
    env = _valid_envelope()
    del env["headers"]["Authorization"]
    r = _client(_FakeAuth()).post("/auth", json=env)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_signature"


@pytest.mark.parametrize(
    ("reason", "status"),
    [
        (RejectionReason.BINDING_MISMATCH, 403),
        (RejectionReason.INVALID_SHAPE, 400),
        (RejectionReason.STALE, 401),
        (RejectionReason.ARN_NOT_ALLOWED, 403),
    ],
)
def test_domain_rejection_status_mapping(reason: RejectionReason, status: int) -> None:
    auth = _FakeAuth(error=reject(reason, "거부"))
    r = _client(auth).post("/auth", json=_valid_envelope())
    assert r.status_code == status
    assert r.json()["error"] == reason.value


def test_verification_failed_401() -> None:
    auth = _FakeAuth(error=VerificationRejected("서명 무효"))
    r = _client(auth).post("/auth", json=_valid_envelope())
    assert r.status_code == 401
    assert r.json()["error"] == "verification_failed"


def test_infra_error_502() -> None:
    auth = _FakeAuth(error=RuntimeError("STS 전송 실패"))
    r = _client(auth).post("/auth", json=_valid_envelope())
    assert r.status_code == 502
    assert r.json()["error"] == "upstream_error"


def test_healthz() -> None:
    r = _client(_FakeAuth()).get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
