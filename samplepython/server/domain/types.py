"""도메인 코어의 값 타입.

수신 어댑터가 추출해 인바운드 포트로 넘기는 값과, 아웃바운드 포트가 주고받는 값을 담는다.
코어를 전송 기술에서 떼어 두기 위해 net/http 같은 프레임워크 타입을 쓰지 않고, 메서드/헤더는
문자열/딕셔너리로만 받는다(Go domain 패키지의 표준 라이브러리 전용 원칙에 대응).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


class ProofForm(StrEnum):
    """증명 형태(SigV4 서명을 어떻게 실었는지). 두 형태는 같은 SignedRequest 로 수렴하되,
    형태에 따라 코어의 형태 검증(기대 메서드)과 신선도 판단(클라이언트 지정 만료 반영 여부)이
    갈린다. 어댑터가 수신 형태를 판별해 채운다.
    """

    # 헤더 기반 서명(Authorization 헤더에 SignedHeaders, POST GetCallerIdentity, 예: Vault).
    # 빈 값(제로값)도 이 형태로 취급해 하위호환을 지킨다(어댑터에서 기본값으로 사용).
    HEADER = "header"

    # pre-signed URL 형태(SigV4 쿼리 서명, GET GetCallerIdentity, 클라이언트가 X-Amz-Expires 로
    # 만료를 직접 지정, 예: AWS IAM Authenticator).
    PRESIGNED = "presigned"


@dataclass(frozen=True)
class PreservedRequest:
    """STS 로 재구성 없이 그대로 전달할 원본 서명 요청을 담는 불투명 값이다. 코어는 이 안을
    해석하지 않는다. 필드 구성은 수신 어댑터와 STS 신원 검증 어댑터가 공유해 소유한다.
    """

    method: str
    url: str
    header: dict[str, list[str]]
    body: bytes


@dataclass(frozen=True)
class SignedRequest:
    """수신 어댑터가 서명된 GetCallerIdentity 요청을 파싱해 코어로 넘기는 값이다. 코어가 로컬
    판단에 쓰는 추출 스칼라와, STS 위임에 그대로 쓸 원본 요청을 함께 담는다.
    """

    # 증명 형태(header/presigned). 코어는 형태별 기대 메서드로 형태를 검증하고, presigned 일
    # 때만 아래 expiry 를 신선도 판단에 반영한다. 빈 값은 header 로 취급한다.
    form: ProofForm

    # 서명 범위에 포함된 서버 바인딩 헤더 값이다(2단계 검증 대상).
    binding_value: str

    # 전달 요청의 HTTP 메서드다(3단계 형태 검증용).
    method: str

    # 어댑터가 요청 바디/쿼리에서 파싱한 액션 이름이다(3단계 형태 검증용). 코어는 이 값이
    # GetCallerIdentity 인지 대조한다.
    action: str

    # 요청 서명 시각이다(4단계 신선도 검증용). tz-aware UTC.
    signed_at: datetime

    # 원본 서명 요청. 코어는 내용을 들여다보지 않고 신원 검증 포트로 넘기기만 한다.
    original: PreservedRequest

    # presigned 에서 클라이언트가 X-Amz-Expires 로 지정한 만료(서명 시각 기준 유효 구간 길이)다.
    # header 형태는 0 이다. 서버는 이 값을 맹신하지 않고 자체 최대 age 와 교집합(min)으로만
    # 신선도에 반영한다(4단계).
    expiry: timedelta = timedelta(0)


@dataclass(frozen=True)
class Identity:
    """STS 가 검증해 돌려준 호출자 신원이다. 코어는 ARN 을 허용 신원 목록과 대조한다(7단계)."""

    # 허용 목록 대조 대상.
    arn: str

    # 감사/로그 용도의 부가 정보로, 판단에는 쓰지 않는다.
    account: str = ""
    user_id: str = ""


@dataclass(frozen=True)
class Credential:
    """모든 검증을 통과한 신원에 발급하는 서버 자체 접근 자격이다(8단계). 구체 형태(예: JWT)는
    자격 발급 어댑터가 정한다.
    """

    token: str
    expires_at: datetime


@dataclass(frozen=True)
class VerifiedToken:
    """서명 검증을 통과한 토큰에서 뽑아낸 클레임이다. 코어는 이 값으로 만료(expires_at)와
    발급자(issuer)/대상(audience)을 판단한다. 시각 클레임은 초 단위 Unix 시각을 datetime 으로
    되살린 값이다(발급이 초 단위로 자르는 것과 대칭).

    클레임 표현은 계층별로 셋이 대칭을 이룬다(하나를 추가/변경하면 나머지도 함께 갱신):
    issuer.Claims(JWT 와이어, int unix) <-> 이 VerifiedToken(도메인, datetime) <->
    inbound verify 응답(HTTP, RFC3339).
    """

    issuer: str
    subject: str
    audience: str
    expires_at: datetime
    issued_at: datetime
    jti: str
    account: str
    user_id: str


@dataclass(frozen=True)
class AuthenticateInput:
    """인증 유스케이스 입력. 수신 어댑터가 파싱한 서명 요청을 담는다."""

    request: SignedRequest


@dataclass(frozen=True)
class AuthenticateOutput:
    """인증 성공 결과. 발급된 자격과 검증된 신원을 담는다."""

    credential: Credential
    identity: Identity


@dataclass(frozen=True)
class VerifyTokenInput:
    """토큰 검증 유스케이스 입력. 수신 어댑터가 요청에서 뽑은 발급 토큰 문자열을 담는다."""

    token: str


@dataclass(frozen=True)
class VerifyTokenOutput:
    """토큰 검증 성공 결과. 검증된 토큰의 클레임을 담는다."""

    claims: VerifiedToken
