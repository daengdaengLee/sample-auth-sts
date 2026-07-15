"""도메인 Service(/auth) 코어의 2~8단계 결정 논리 테스트."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from server.domain.errors import RejectionError, RejectionReason, VerificationRejected
from server.domain.service import Service
from server.domain.types import (
    AuthenticateInput,
    PreservedRequest,
    ProofForm,
    SignedRequest,
)
from tests.server.fakes import FakeClock, FakeIssuer, FakePolicy, FakeVerifier

_NOW = datetime(2026, 7, 9, 12, 0, 30, tzinfo=UTC)
_SIGNED_AT = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)


def _signed_request(
    *,
    form: ProofForm = ProofForm.HEADER,
    binding: str = "https://server.example/audience",
    method: str = "POST",
    action: str = "GetCallerIdentity",
    signed_at: datetime = _SIGNED_AT,
    expiry: timedelta = timedelta(0),
) -> SignedRequest:
    return SignedRequest(
        form=form,
        binding_value=binding,
        method=method,
        action=action,
        signed_at=signed_at,
        expiry=expiry,
        original=PreservedRequest(
            method=method, url="https://sts.amazonaws.com/", header={}, body=b""
        ),
    )


def _service(**kwargs: object) -> tuple[Service, FakeVerifier, FakeIssuer]:
    verifier = FakeVerifier()
    issuer = FakeIssuer()
    svc = Service(FakePolicy(), FakeClock(_NOW), verifier, issuer)
    return svc, verifier, issuer


def test_success_issues_credential() -> None:
    svc, verifier, issuer = _service()
    out = svc.authenticate(AuthenticateInput(request=_signed_request()))
    assert verifier.called
    assert issuer.called
    assert out.identity.arn == "arn:aws:iam::123456789012:role/workload"


def test_binding_mismatch_rejected_before_delegation() -> None:
    svc, verifier, _ = _service()
    with pytest.raises(RejectionError) as ei:
        svc.authenticate(AuthenticateInput(request=_signed_request(binding="https://evil/aud")))
    assert ei.value.reason == RejectionReason.BINDING_MISMATCH
    assert not verifier.called  # 위임 전에 거부


@pytest.mark.parametrize(
    ("form", "method"),
    [(ProofForm.HEADER, "GET"), (ProofForm.PRESIGNED, "POST")],
)
def test_invalid_shape_wrong_method(form: ProofForm, method: str) -> None:
    svc, _, _ = _service()
    with pytest.raises(RejectionError) as ei:
        svc.authenticate(AuthenticateInput(request=_signed_request(form=form, method=method)))
    assert ei.value.reason == RejectionReason.INVALID_SHAPE


def test_invalid_shape_wrong_action() -> None:
    svc, _, _ = _service()
    with pytest.raises(RejectionError) as ei:
        svc.authenticate(AuthenticateInput(request=_signed_request(action="DeleteEverything")))
    assert ei.value.reason == RejectionReason.INVALID_SHAPE


def test_stale_future_signed_at_rejected() -> None:
    svc, _, _ = _service()
    future = _NOW + timedelta(seconds=10)
    with pytest.raises(RejectionError) as ei:
        svc.authenticate(AuthenticateInput(request=_signed_request(signed_at=future)))
    assert ei.value.reason == RejectionReason.STALE


def test_stale_too_old_rejected() -> None:
    svc, _, _ = _service()
    old = _NOW - timedelta(minutes=6)
    with pytest.raises(RejectionError) as ei:
        svc.authenticate(AuthenticateInput(request=_signed_request(signed_at=old)))
    assert ei.value.reason == RejectionReason.STALE


def test_presigned_expiry_shrinks_window() -> None:
    # 서명 후 90초 경과. 서버 max_age 5분이지만 클라이언트 만료 60초라 교집합 60초 -> stale.
    svc, _, _ = _service()
    signed = _NOW - timedelta(seconds=90)
    with pytest.raises(RejectionError) as ei:
        svc.authenticate(
            AuthenticateInput(
                request=_signed_request(
                    form=ProofForm.PRESIGNED,
                    method="GET",
                    signed_at=signed,
                    expiry=timedelta(seconds=60),
                )
            )
        )
    assert ei.value.reason == RejectionReason.STALE


def test_arn_not_allowed_rejected() -> None:
    verifier = FakeVerifier()
    verifier._identity = type(verifier._identity)(arn="arn:aws:iam::999:role/other")
    svc = Service(FakePolicy(), FakeClock(_NOW), verifier, FakeIssuer())
    with pytest.raises(RejectionError) as ei:
        svc.authenticate(AuthenticateInput(request=_signed_request()))
    assert ei.value.reason == RejectionReason.ARN_NOT_ALLOWED


def test_verifier_error_propagated() -> None:
    verifier = FakeVerifier(error=VerificationRejected("서명 무효"))
    svc = Service(FakePolicy(), FakeClock(_NOW), verifier, FakeIssuer())
    with pytest.raises(VerificationRejected):
        svc.authenticate(AuthenticateInput(request=_signed_request()))
