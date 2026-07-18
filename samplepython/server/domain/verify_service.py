"""토큰 검증 유스케이스(/verify)의 도메인 코어.

서명 검증(아웃바운드 위임)은 TokenInspector 에 맡기고, 만료(exp)와 발급자(iss)/대상(aud)
판단은 코어에서 수행한다. Service(/auth)와 대칭 구조다.
"""

from __future__ import annotations

from server.domain.errors import RejectionReason, reject
from server.domain.ports import Clock, TokenInspector, VerifyPolicy
from server.domain.types import VerifyTokenInput, VerifyTokenOutput


class VerifyService:
    """인바운드 포트 TokenVerifier 의 구현. 시계/검사기와 검증 정책 포트를 주입해 토큰을
    검증한다.
    """

    def __init__(self, clock: Clock, inspector: TokenInspector, policy: VerifyPolicy) -> None:
        self._clock = clock
        self._inspector = inspector
        self._policy = policy

    def verify_token(self, in_: VerifyTokenInput) -> VerifyTokenOutput:
        """토큰 한 건에 대해 서명(위임) -> 만료 -> 발급자/대상 순으로 판단하고, 모두 통과하면
        클레임을 돌려준다. 서명/구조 실패는 검사기가 VerificationRejected 로 전파하고, 만료/
        발급자/대상 불일치는 로컬 판단이므로 RejectionError 로 던진다.
        """

        # 서명/구조 검증은 아웃바운드 검사기에 위임한다. 무효 토큰(VerificationRejected)이나
        # 내부 실패(일반 예외)를 구분 없이 그대로 전파해, 수신 어댑터가 도메인 타입으로 가른다.
        vt = self._inspector.inspect(in_.token)

        # 만료 검사: 현재 시각이 exp 이상이면(exp 를 지났으면) 만료다. exp 는 초 단위라 발급의
        # 초 단위 절삭과 대칭으로 판단한다.
        if not self._clock.now() < vt.expires_at:
            raise reject(RejectionReason.TOKEN_EXPIRED, "토큰이 만료됨(exp 경과)")

        # 발급자/대상 검사: 이 서버가 발급한 토큰인지(iss)와 이 서버의 대상으로 발급됐는지(aud)를
        # 확인해, 다른 발급자/대상의 토큰을 받아들이지 않는다.
        if vt.issuer != self._policy.expected_issuer():
            raise reject(
                RejectionReason.ISSUER_MISMATCH,
                "토큰 iss 클레임이 발급자 기대값과 일치하지 않음",
            )
        if vt.audience != self._policy.expected_audience():
            raise reject(
                RejectionReason.AUDIENCE_MISMATCH,
                "토큰 aud 클레임이 대상 기대값과 일치하지 않음",
            )

        return VerifyTokenOutput(claims=vt)
