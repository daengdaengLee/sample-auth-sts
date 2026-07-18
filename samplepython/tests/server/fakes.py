"""도메인 테스트용 손수 만든 fake(외부 목 라이브러리 없음). 호출/미호출 스파이와 충실도 단언에
쓴다(Go domain/fakes_test.go 에 대응).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from server.domain.errors import VerificationRejected
from server.domain.types import Credential, Identity, PreservedRequest, VerifiedToken


class FakeClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


class FakePolicy:
    def __init__(
        self,
        binding: str = "https://server.example/audience",
        max_age: timedelta = timedelta(minutes=5),
        allowed: frozenset[str] = frozenset({"arn:aws:iam::123456789012:role/workload"}),
    ) -> None:
        self._binding = binding
        self._max_age = max_age
        self._allowed = allowed

    def expected_binding(self) -> str:
        return self._binding

    def max_age(self) -> timedelta:
        return self._max_age

    def is_allowed_arn(self, arn: str) -> bool:
        return arn in self._allowed


class FakeVerifier:
    def __init__(self, identity: Identity | None = None, error: Exception | None = None) -> None:
        self._identity = identity or Identity(
            arn="arn:aws:iam::123456789012:role/workload",
            account="123456789012",
            user_id="AIDAEXAMPLE",
        )
        self._error = error
        self.called = False
        self.got_req: PreservedRequest | None = None

    def verify_identity(self, req: PreservedRequest) -> Identity:
        self.called = True
        self.got_req = req
        if self._error is not None:
            raise self._error
        return self._identity


class FakeIssuer:
    def __init__(
        self, credential: Credential | None = None, error: Exception | None = None
    ) -> None:
        self._credential = credential or Credential(
            token="header.payload.sig",
            expires_at=datetime.fromtimestamp(0),
        )
        self._error = error
        self.called = False
        self.got_id: Identity | None = None

    def issue_credential(self, identity: Identity) -> Credential:
        self.called = True
        self.got_id = identity
        if self._error is not None:
            raise self._error
        return self._credential


class FakeInspector:
    def __init__(self, token: VerifiedToken | None = None, error: Exception | None = None) -> None:
        self._token = token
        self._error = error

    def inspect(self, token: str) -> VerifiedToken:
        if self._error is not None:
            raise self._error
        assert self._token is not None
        return self._token


class FakeVerifyPolicy:
    def __init__(self, issuer: str, audience: str) -> None:
        self._issuer = issuer
        self._audience = audience

    def expected_issuer(self) -> str:
        return self._issuer

    def expected_audience(self) -> str:
        return self._audience


def make_verification_rejected(reason: str = "무효") -> VerificationRejected:
    return VerificationRejected(reason)
