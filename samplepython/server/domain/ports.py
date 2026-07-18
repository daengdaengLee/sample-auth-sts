"""포트 정의(인바운드/아웃바운드). 헥사고날 아키텍처의 추상 경계다.

인바운드(구동) 포트: 외부에서 코어를 호출하는 입구(Authenticator, TokenVerifier).
아웃바운드(피구동) 포트: 코어가 일을 끝내기 위해 의존하는 추상(IdentityVerifier,
CredentialIssuer, TokenInspector, VerifyPolicy, Clock, Policy).

typing.Protocol 로 정의해 구현 클래스가 명시적 상속 없이 구조적으로 만족하게 하고, mypy 가
정적으로 준수를 검사한다(Go 의 `var _ Iface = (*T)(nil)` 컴파일타임 단언에 대응).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Protocol

from server.domain.types import (
    AuthenticateInput,
    AuthenticateOutput,
    Credential,
    Identity,
    PreservedRequest,
    VerifiedToken,
    VerifyTokenInput,
    VerifyTokenOutput,
)


class Authenticator(Protocol):
    """ "인증 요청을 처리한다" 인바운드(구동) 포트. 수신 어댑터가 파싱한 서명 요청을 이 포트로
    넘기면 코어가 2~8단계 결정 논리를 수행하고 통과 시 자격을 발급한다.
    """

    def authenticate(self, in_: AuthenticateInput) -> AuthenticateOutput: ...


class TokenVerifier(Protocol):
    """ "서버가 발급한 토큰을 검증한다" 인바운드(구동) 포트. Authenticator(/auth)와 짝을 이루는
    /verify 유스케이스의 진입점이다.
    """

    def verify_token(self, in_: VerifyTokenInput) -> VerifyTokenOutput: ...


class IdentityVerifier(Protocol):
    """STS 위임의 추상(신원 검증 아웃바운드 포트). 보존된 원본 서명 요청을 그대로 넘기면 호출자
    신원(ARN 등)을 돌려받는다(5~6단계). 위임 대상 엔드포인트가 허용 목록의 진짜 STS 인지(5단계)는
    이 포트를 구현하는 어댑터가 경계에서 강제한다.

    에러 계약: 무자격(클라이언트측 거절)은 VerificationRejected 로(감싸서라도) 전파하고, 전송
    실패/5xx/파싱 불가 같은 인프라 실패는 일반 예외로 전파한다.
    """

    def verify_identity(self, req: PreservedRequest) -> Identity: ...


class CredentialIssuer(Protocol):
    """검증된 신원에 서버 자체 접근 자격을 발급하는 아웃바운드 포트(8단계)."""

    def issue_credential(self, identity: Identity) -> Credential: ...


class TokenInspector(Protocol):
    """서버가 발급한 토큰의 서명/구조를 검증하는 아웃바운드 포트(/verify). 서명이 유효한지까지만
    책임지며, 만료/발급자/대상 같은 정책 판단은 코어(TokenVerifier 구현)가 한다.

    에러 계약: 무효 토큰(구조/서명/헤더 alg 불일치)은 VerificationRejected 로 전파하고, 내부
    실패는 일반 예외로 전파한다.
    """

    def inspect(self, token: str) -> VerifiedToken: ...


class VerifyPolicy(Protocol):
    """토큰 검증(/verify)에 코어가 쓰는 기대값을 제공하는 아웃바운드 포트. 발급 설정(jwt 섹션)에서
    온 iss/aud 기대값을 노출한다.
    """

    def expected_issuer(self) -> str: ...

    def expected_audience(self) -> str: ...


class Clock(Protocol):
    """신선도 판단에 쓸 현재 시각을 제공하는 아웃바운드 포트(4단계). 테스트에서 시각을 고정할 수
    있도록 포트로 둔다. tz-aware UTC 를 돌려준다.
    """

    def now(self) -> datetime: ...


class Policy(Protocol):
    """코어가 판단에 쓰는 정책/설정 값을 제공하는 아웃바운드 포트. 코어가 실제로 읽는 값만
    노출한다. STS 엔드포인트 허용 목록은 코어가 쓰지 않고 신원 검증 어댑터가 경계에서 강제하므로
    여기 두지 않는다(인터페이스 분리).
    """

    def expected_binding(self) -> str: ...

    def max_age(self) -> timedelta: ...

    def is_allowed_arn(self, arn: str) -> bool: ...
