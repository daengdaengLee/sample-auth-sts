"""도메인 에러 타입.

로컬 검증 거부(RejectionError)와 위임 검증 무자격(VerificationRejected)을 구분한다. 수신
어댑터는 이 두 타입만으로 응답 상태를 가른다(무자격 4xx 대 인프라 실패 5xx). 아웃바운드
어댑터는 무자격을 VerificationRejected 로(감싸서라도) 전파해, 수신 어댑터가 특정 어댑터
패키지에 의존하지 않고 도메인 타입만으로 분류하게 한다.

Go 의 errors.As + Unwrap 체인에 대응해, as_rejection/as_verification_rejected 는 예외의
__cause__ 체인을 따라가며 해당 타입을 찾는다.
"""

from __future__ import annotations

from enum import StrEnum


class RejectionReason(StrEnum):
    """로컬 검증 단계에서 요청을 거부한 사유. 수신 어댑터가 로그에 남기고 응답으로 매핑한다."""

    # 서버 바인딩 헤더 값이 기대값과 다를 때(2단계, 혼동된 대리자).
    BINDING_MISMATCH = "binding_mismatch"

    # 전달 요청이 GetCallerIdentity 호출이 아닐 때(3단계, 전달 요청 검증).
    INVALID_SHAPE = "invalid_shape"

    # 요청이 허용된 최대 age 를 벗어났거나 미래 시각일 때(4단계, 재전송).
    STALE = "stale"

    # STS 가 돌려준 ARN 이 허용 신원 목록에 없을 때(7단계, 반환 신원 검증).
    ARN_NOT_ALLOWED = "arn_not_allowed"

    # 검증 대상 토큰의 exp 가 현재 시각을 지났을 때(/verify 만료 검사).
    TOKEN_EXPIRED = "token_expired"

    # 토큰의 iss 클레임이 이 서버의 발급자 기대값과 다를 때(/verify).
    ISSUER_MISMATCH = "issuer_mismatch"

    # 토큰의 aud 클레임이 이 서버의 대상 기대값과 다를 때(/verify).
    AUDIENCE_MISMATCH = "audience_mismatch"


class RejectionError(Exception):
    """코어의 로컬 검증이 요청을 거부했음을 나타내는 에러. reason 으로 어느 검증에서 걸렸는지
    구분한다. 아웃바운드 포트의 인프라 실패는 이 타입이 아니라 원래 에러 그대로 전파되므로,
    어댑터는 둘을 구분해 응답 상태를 정할 수 있다.
    """

    def __init__(self, reason: RejectionReason, message: str) -> None:
        self.reason = reason
        self.message = message
        super().__init__(f"요청 거부({reason.value}): {message}")


class VerificationRejected(Exception):
    """신원 검증 포트(IdentityVerifier)나 토큰 검사 포트(TokenInspector)가 "무자격"(클라이언트측
    거절)을 나타낼 때 쓰는 도메인 에러. 코어는 이 에러를 그대로 전파하므로, 수신 어댑터는 이
    타입 여부로 무자격 응답과 인프라 실패를 가른다. 아웃바운드 어댑터(STS 등)는 이 타입을
    (__cause__ 로 감싸서라도) 전파한다.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"신원 검증 거절: {reason}")


def reject(reason: RejectionReason, message: str) -> RejectionError:
    """RejectionError 를 만드는 내부 헬퍼."""

    return RejectionError(reason, message)


def as_rejection(err: BaseException | None) -> RejectionError | None:
    """err 가(원인 체인으로 감싸져 있더라도) RejectionError 인지 찾아 돌려준다. 수신 어댑터가
    거부(무자격 응답)와 인프라 실패(5xx)를 구분하는 데 쓴다(Go errors.As 대응).
    """

    while err is not None:
        if isinstance(err, RejectionError):
            return err
        err = err.__cause__
    return None


def as_verification_rejected(err: BaseException | None) -> VerificationRejected | None:
    """err 가(원인 체인으로 감싸져 있더라도) VerificationRejected 인지 찾아 돌려준다. 수신
    어댑터가 무자격 응답과 인프라 실패를 구분하는 데 쓴다(Go errors.As 대응).
    """

    while err is not None:
        if isinstance(err, VerificationRejected):
            return err
        err = err.__cause__
    return None
