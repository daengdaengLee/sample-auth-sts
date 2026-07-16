"""/verify 수신 어댑터. 서버가 발급한 JWT 를 파싱해 인바운드 포트로 넘기고, 결과를 HTTP 로
매핑한다.

요청 엔벨로프 오류(파싱 실패/빈 토큰/상한 초과)는 도메인 호출 전에 4xx 로 거르고, 통과한 토큰만
코어로 넘긴다. 검증 실패(서명 무효/만료/클레임 불일치)는 401, 성공은 200 이다.
"""

from __future__ import annotations

from server.adapter.inbound.http_util import ClientError, rfc3339
from server.domain.errors import as_rejection, as_verification_rejected
from server.domain.ports import TokenVerifier
from server.domain.types import VerifyTokenInput


class VerifyHandler:
    """/verify 핸들러. 인바운드 포트 TokenVerifier 를 주입받아 파싱한 토큰을 코어로 넘긴다."""

    def __init__(self, verify: TokenVerifier) -> None:
        self._verify = verify

    def handle(self, payload: object) -> tuple[int, dict[str, str]]:
        """파싱된 JSON 엔벨로프를 받아 (status, body) 를 돌려주는 동기 처리 본체."""

        try:
            return self._handle(payload)
        except ClientError as e:
            return e.status, {"error": e.code, "message": e.message}

    def _handle(self, payload: object) -> tuple[int, dict[str, str]]:
        if not isinstance(payload, dict):
            raise ClientError(400, "invalid_body", "요청 본문이 객체가 아님")
        token = payload.get("token")
        if not isinstance(token, str):
            raise ClientError(400, "invalid_body", "token 은 문자열이어야 함")

        # 빈 토큰은 검증할 대상이 없는 형식 오류이므로 코어 호출 전에 400 으로 거른다.
        if token == "":
            raise ClientError(400, "invalid_body", "token 필드가 비어 있음")

        try:
            out = self._verify.verify_token(VerifyTokenInput(token=token))
        except Exception as e:  # noqa: BLE001 - Go writeVerifyError 처럼 모든 코어 오류를 매핑한다
            return _map_error(e)

        claims = out.claims
        return 200, {
            "iss": claims.issuer,
            "sub": claims.subject,
            "aud": claims.audience,
            "exp": rfc3339(claims.expires_at),
            "iat": rfc3339(claims.issued_at),
            "jti": claims.jti,
            "account": claims.account,
            "user_id": claims.user_id,
        }


def _map_error(err: Exception) -> tuple[int, dict[str, str]]:
    """도메인/어댑터가 던진 예외를 (status, body) 로 매핑한다. 무효 토큰(서명/구조 실패
    VerificationRejected, 만료/발급자/대상 불일치 RejectionError)은 모두 401 로, 그 외 내부 오류는
    500 으로 매핑한다.
    """

    ve = as_verification_rejected(err)
    if ve is not None:
        return 401, {
            "error": "invalid_token",
            "message": "토큰 검증에 실패함(서명 무효/구조 오류)",
        }

    re = as_rejection(err)
    if re is not None:
        return 401, {"error": re.reason.value, "message": re.message}

    # 그 외는 내부 실패다. 검증 경로에는 외부 위임이 없어 실무상 거의 없지만, 예기치 못한 오류를
    # 성공/무효로 오분류하지 않도록 500 으로 매핑한다.
    return 500, {"error": "internal_error", "message": "토큰 검증 중 내부 오류"}
