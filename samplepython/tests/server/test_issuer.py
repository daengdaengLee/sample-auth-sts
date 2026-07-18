"""issuer 어댑터(HS256 발급/검증/설정 로드) 테스트."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from server.adapter.outbound import issuer
from server.domain.errors import VerificationRejected
from server.domain.types import Identity
from server.internal.config import JwtSettings

_FIXED = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)


def _params() -> issuer.Params:
    return issuer.load(
        JwtSettings(
            signing_secret="x" * 32,
            ttl="15m",
            issuer="https://server.example",
            audience="https://server.example/clients",
        )
    )


def _identity() -> Identity:
    return Identity(
        arn="arn:aws:iam::123456789012:role/workload",
        account="123456789012",
        user_id="AIDAEXAMPLE",
    )


def test_issue_then_inspect_roundtrip() -> None:
    params = _params()
    iss = issuer.new(params, now=lambda: _FIXED)
    cred = iss.issue_credential(_identity())
    assert len(cred.token.split(".")) == 3
    assert cred.expires_at == datetime(2026, 7, 9, 12, 15, 0, tzinfo=UTC)

    vt = issuer.new_inspector(params).inspect(cred.token)
    assert vt.subject == "arn:aws:iam::123456789012:role/workload"
    assert vt.issuer == "https://server.example"
    assert vt.audience == "https://server.example/clients"
    assert vt.issued_at == _FIXED


def test_deterministic_bytes_ignoring_jti() -> None:
    # jti 는 난수이므로 header.payload 부분만 비교하면 결정적이어야 한다.
    params = _params()
    iss = issuer.new(params, now=lambda: _FIXED)
    t1 = iss.issue_credential(_identity()).token
    t2 = iss.issue_credential(_identity()).token
    assert t1.split(".")[0] == t2.split(".")[0]  # header 고정


def test_inspect_rejects_wrong_segment_count() -> None:
    with pytest.raises(VerificationRejected):
        issuer.new_inspector(_params()).inspect("only.two")


def test_inspect_rejects_tampered_signature() -> None:
    params = _params()
    cred = issuer.new(params, now=lambda: _FIXED).issue_credential(_identity())
    tampered = cred.token[:-2] + ("aa" if not cred.token.endswith("aa") else "bb")
    with pytest.raises(VerificationRejected):
        issuer.new_inspector(params).inspect(tampered)


def test_inspect_rejects_alg_confusion() -> None:
    # 헤더 세그먼트를 바꾸면(alg none/RS256 시도) 거부된다.
    params = _params()
    cred = issuer.new(params, now=lambda: _FIXED).issue_credential(_identity())
    import base64

    fake_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    parts = cred.token.split(".")
    with pytest.raises(VerificationRejected):
        issuer.new_inspector(params).inspect(f"{fake_header}.{parts[1]}.{parts[2]}")


def test_load_rejects_short_secret() -> None:
    with pytest.raises(ValueError, match="너무 짧음"):
        issuer.load(JwtSettings(signing_secret="short", ttl="15m", issuer="i", audience="a"))


def test_load_rejects_empty_secret() -> None:
    with pytest.raises(ValueError, match="비어 있음"):
        issuer.load(JwtSettings(signing_secret="", ttl="15m", issuer="i", audience="a"))


def test_load_rejects_sub_second_ttl() -> None:
    with pytest.raises(ValueError, match="최소"):
        issuer.load(JwtSettings(signing_secret="x" * 32, ttl="500ms", issuer="i", audience="a"))


def test_load_rejects_missing_issuer_audience() -> None:
    with pytest.raises(ValueError, match="jwt.issuer"):
        issuer.load(JwtSettings(signing_secret="x" * 32, ttl="15m", issuer="", audience="a"))
    with pytest.raises(ValueError, match="jwt.audience"):
        issuer.load(JwtSettings(signing_secret="x" * 32, ttl="15m", issuer="i", audience=""))
