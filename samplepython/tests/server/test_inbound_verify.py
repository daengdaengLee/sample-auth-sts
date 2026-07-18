"""/verify 수신 어댑터 테스트."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from server.adapter.inbound.router import create_app
from server.domain.errors import RejectionReason, VerificationRejected, reject
from server.domain.types import (
    AuthenticateInput,
    AuthenticateOutput,
    VerifiedToken,
    VerifyTokenInput,
    VerifyTokenOutput,
)


class _FakeAuth:
    def authenticate(self, in_: AuthenticateInput) -> AuthenticateOutput:  # pragma: no cover
        raise AssertionError("auth 는 이 테스트에서 호출되지 않음")


class _FakeVerify:
    def __init__(self, error: Exception | None = None) -> None:
        self._error = error

    def verify_token(self, in_: VerifyTokenInput) -> VerifyTokenOutput:
        if self._error is not None:
            raise self._error
        return VerifyTokenOutput(
            claims=VerifiedToken(
                issuer="https://server.example",
                subject="arn:aws:iam::123456789012:role/workload",
                audience="https://server.example/clients",
                expires_at=datetime(2026, 7, 9, 12, 15, tzinfo=UTC),
                issued_at=datetime(2026, 7, 9, 12, 0, tzinfo=UTC),
                jti="abc",
                account="123456789012",
                user_id="AIDAEXAMPLE",
            )
        )


def _client(verify: _FakeVerify) -> TestClient:
    return TestClient(create_app(logging.getLogger("t"), _FakeAuth(), verify))


def test_verify_success() -> None:
    r = _client(_FakeVerify()).post("/verify", json={"token": "h.p.s"})
    assert r.status_code == 200
    body = r.json()
    assert body["sub"] == "arn:aws:iam::123456789012:role/workload"
    assert body["exp"] == "2026-07-09T12:15:00Z"
    assert body["iat"] == "2026-07-09T12:00:00Z"
    assert body["account"] == "123456789012"


def test_empty_token_400() -> None:
    r = _client(_FakeVerify()).post("/verify", json={"token": ""})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_body"


def test_invalid_token_401() -> None:
    r = _client(_FakeVerify(error=VerificationRejected("서명 무효"))).post(
        "/verify", json={"token": "bad"}
    )
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_token"


def test_rejection_maps_to_401_with_reason() -> None:
    r = _client(_FakeVerify(error=reject(RejectionReason.TOKEN_EXPIRED, "만료"))).post(
        "/verify", json={"token": "expired"}
    )
    assert r.status_code == 401
    assert r.json()["error"] == "token_expired"


def test_internal_error_500() -> None:
    r = _client(_FakeVerify(error=RuntimeError("boom"))).post("/verify", json={"token": "x"})
    assert r.status_code == 500
    assert r.json()["error"] == "internal_error"
