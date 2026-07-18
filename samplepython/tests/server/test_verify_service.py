"""도메인 VerifyService(/verify) 코어 테스트."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from server.domain.errors import RejectionError, RejectionReason, VerificationRejected
from server.domain.types import VerifiedToken, VerifyTokenInput
from server.domain.verify_service import VerifyService
from tests.server.fakes import FakeClock, FakeInspector, FakeVerifyPolicy

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)


def _token(
    *,
    issuer: str = "https://server.example",
    audience: str = "https://server.example/clients",
    expires_at: datetime = _NOW + timedelta(minutes=10),
) -> VerifiedToken:
    return VerifiedToken(
        issuer=issuer,
        subject="arn:aws:iam::123456789012:role/workload",
        audience=audience,
        expires_at=expires_at,
        issued_at=_NOW,
        jti="abc",
        account="123456789012",
        user_id="AIDAEXAMPLE",
    )


def _service(token: VerifiedToken) -> VerifyService:
    return VerifyService(
        FakeClock(_NOW),
        FakeInspector(token=token),
        FakeVerifyPolicy("https://server.example", "https://server.example/clients"),
    )


def test_success() -> None:
    out = _service(_token()).verify_token(VerifyTokenInput(token="t"))
    assert out.claims.subject == "arn:aws:iam::123456789012:role/workload"


def test_expired() -> None:
    svc = _service(_token(expires_at=_NOW - timedelta(seconds=1)))
    with pytest.raises(RejectionError) as ei:
        svc.verify_token(VerifyTokenInput(token="t"))
    assert ei.value.reason == RejectionReason.TOKEN_EXPIRED


def test_issuer_mismatch() -> None:
    svc = _service(_token(issuer="https://evil"))
    with pytest.raises(RejectionError) as ei:
        svc.verify_token(VerifyTokenInput(token="t"))
    assert ei.value.reason == RejectionReason.ISSUER_MISMATCH


def test_audience_mismatch() -> None:
    svc = _service(_token(audience="https://evil/aud"))
    with pytest.raises(RejectionError) as ei:
        svc.verify_token(VerifyTokenInput(token="t"))
    assert ei.value.reason == RejectionReason.AUDIENCE_MISMATCH


def test_inspector_rejection_propagated() -> None:
    svc = VerifyService(
        FakeClock(_NOW),
        FakeInspector(error=VerificationRejected("서명 무효")),
        FakeVerifyPolicy("https://server.example", "https://server.example/clients"),
    )
    with pytest.raises(VerificationRejected):
        svc.verify_token(VerifyTokenInput(token="t"))
