"""인증 유스케이스(/auth)의 도메인 코어.

README "서버 > 요청 처리"의 2~8단계 결정 논리를 순서대로 오케스트레이션한다. 값싼 로컬 검증
(바인딩/형태/신선도)을 네트워크 위임(STS) 앞에 두어, 위임 비용을 치르기 전에 거를 수 있는
요청을 먼저 거른다.
"""

from __future__ import annotations

from datetime import timedelta

from server.domain.errors import RejectionReason, reject
from server.domain.ports import Clock, CredentialIssuer, IdentityVerifier, Policy
from server.domain.types import AuthenticateInput, AuthenticateOutput, ProofForm

# 전달 요청이 GetCallerIdentity 호출인지 확인할 때 대조하는 액션 이름.
_GET_CALLER_IDENTITY_ACTION = "GetCallerIdentity"

# 형태 검증에 쓰는 메서드 상수. 코어를 전송 기술에서 떼어 두기 위해 문자열로 둔다. 헤더 기반은
# POST GetCallerIdentity, presigned 는 GET GetCallerIdentity 이므로 형태별로 기대 메서드가 다르다.
_METHOD_POST = "POST"
_METHOD_GET = "GET"


class Service:
    """인바운드 포트 Authenticator 의 구현. 네 개의 아웃바운드 포트(정책/시계/신원 검증/발급)를
    주입해 2~8단계를 수행한다.
    """

    def __init__(
        self,
        policy: Policy,
        clock: Clock,
        verifier: IdentityVerifier,
        issuer: CredentialIssuer,
    ) -> None:
        self._policy = policy
        self._clock = clock
        self._verifier = verifier
        self._issuer = issuer

    def authenticate(self, in_: AuthenticateInput) -> AuthenticateOutput:
        """서명된 요청 한 건에 대해 2~8단계를 순서대로 판단하고, 모두 통과하면 서버 자체 접근
        자격을 발급한다. 어느 로컬 검증이든 실패하면 RejectionError 를 던지고, 아웃바운드
        포트(STS/발급)의 예외는 그대로 전파한다.
        """

        req = in_.request

        # 2단계. 서버 바인딩 헤더 검증(혼동된 대리자 완화): 바인딩 값이 이 서버만의 고유
        # 기대값과 일치하는지 본다.
        if req.binding_value != self._policy.expected_binding():
            raise reject(
                RejectionReason.BINDING_MISMATCH,
                "서버 바인딩 헤더 값이 기대값과 일치하지 않음",
            )

        # 3단계. 전달 요청 형태 검증: 위임할 요청이 정확히 GetCallerIdentity 호출인지 확인해,
        # 신원 조회가 아닌 다른 요청을 대신 내보내는 통로가 되지 않게 한다. 기대 메서드는 형태별로
        # 다르다(헤더 기반은 POST, presigned 는 GET). 빈 form 은 헤더 기반으로 취급한다.
        expected_method = _METHOD_GET if req.form == ProofForm.PRESIGNED else _METHOD_POST
        if req.method != expected_method or req.action != _GET_CALLER_IDENTITY_ACTION:
            raise reject(
                RejectionReason.INVALID_SHAPE,
                "전달 요청이 GetCallerIdentity 호출이 아님",
            )

        # 4단계. 신선도/최대 age 검증(재전송 완화): 시계 포트가 준 현재 시각을 기준으로 요청이
        # 허용된 최대 age 안에 있는지 본다. 음수 age(미래 시각/시계 스큐)도 거부한다.
        #
        # presigned 는 클라이언트가 X-Amz-Expires 로 만료를 정하지만, 서버는 이를 맹신하지 않고
        # 자체 최대 age 를 계속 강제한다. 유효한 최대 age 는 둘의 교집합, 즉 min(서버 최대 age,
        # 클라이언트 만료)이다. 헤더 기반(expiry=0)은 서버 최대 age 만 적용된다.
        max_age = self._policy.max_age()
        if req.form == ProofForm.PRESIGNED and timedelta(0) < req.expiry < max_age:
            max_age = req.expiry
        age = self._clock.now() - req.signed_at
        if age < timedelta(0) or age > max_age:
            raise reject(
                RejectionReason.STALE,
                "요청 서명 시각이 허용된 신선도 구간을 벗어남",
            )

        # 5~6단계. STS 위임: 보존된 원본 서명 요청을 재구성 없이 신원 검증 포트로 그대로 넘겨
        # 호출자 신원(ARN 등)을 돌려받는다. STS 엔드포인트 신뢰(5단계)는 어댑터 경계에서 강제한다.
        # 포트의 예외는 거부가 아니라 인프라 실패이므로 그대로 전파한다.
        identity = self._verifier.verify_identity(req.original)

        # 7단계. 반환 ARN 검증(반환 신원 검증): 돌려받은 ARN 이 허용 신원 목록에 드는지 대조한다.
        # 유효한 AWS 신원이라고 무엇이든 받지는 않는다.
        if not self._policy.is_allowed_arn(identity.arn):
            raise reject(
                RejectionReason.ARN_NOT_ALLOWED,
                "반환된 ARN 이 허용 신원 목록에 없음",
            )

        # 8단계. 자격 발급: 모든 검증을 통과하면 서버 자체 접근 자격을 발급한다.
        cred = self._issuer.issue_credential(identity)

        return AuthenticateOutput(credential=cred, identity=identity)
