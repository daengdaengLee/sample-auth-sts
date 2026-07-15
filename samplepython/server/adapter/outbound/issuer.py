"""자격 발급 어댑터. 도메인 CredentialIssuer 아웃바운드 포트(8단계)를 HS256 JWT 발급으로
구현하고, 같은 대칭키로 /verify 의 TokenInspector 와 VerifyPolicy 도 함께 제공한다.

외부 JWT 라이브러리 없이 표준 라이브러리(hmac + hashlib + json + base64)로 직접 서명한다.
발급과 검증이 같은 소재(고정 헤더 세그먼트, 고정 클레임 순서, 같은 시크릿)를 쓰므로 형식이
어긋날 여지가 없다. HS256 은 대칭키라, /verify 가 같은 시크릿으로 서명을 재계산해 검증한다.

여기서 필요한 것은 "같은 입력 -> 같은 바이트"라는 구현 내부 결정성이지 Go 와의 바이트 동일성이
아니다. 발급(Issuer)과 검증(Inspector)이 모두 파이썬 쪽에서 자기정합적이면 충분하다.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from server.domain.errors import VerificationRejected
from server.domain.ports import CredentialIssuer, TokenInspector, VerifyPolicy
from server.domain.types import Credential, Identity, VerifiedToken
from server.internal.config import JwtSettings
from server.internal.duration import DurationError, parse_duration

# 기본 발급 TTL(jwt.ttl 미설정 시).
_DEFAULT_TTL = timedelta(minutes=15)

# HS256 서명키의 최소 길이(바이트). 256비트 미만의 약한 키는 서명 위조 위험이 있어 부팅 시점에
# 막는다.
_MIN_SECRET_BYTES = 32

# 받아들일 최소 발급 TTL. 발급 시 exp/iat 를 초 단위로 자르므로, 1초 미만 TTL 은 발급 즉시
# 만료된 토큰(exp == iat)이 되어 무의미하다.
_MIN_TTL = timedelta(seconds=1)

# {"alg":"HS256","typ":"JWT"} 를 base64url(no pad) 인코딩한 고정값. 헤더는 항상 같으므로
# 리터럴을 직접 인코딩해, 직렬화 필드 순서 비결정성을 피한다.
_HEADER_SEGMENT = (
    base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode("ascii")
)


def _b64url_encode(data: bytes) -> str:
    """base64url(no pad) 인코딩."""

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(seg: str) -> bytes:
    """base64url(no pad) 디코드. 패딩을 복원해 디코드한다. 잘못된 base64 는 예외를 던진다."""

    padding = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + padding)


def _sign_with(secret: bytes, signing_input: str) -> str:
    """시크릿으로 서명 입력(header.payload)에 HMAC-SHA256 서명을 계산해 base64url(no pad)로
    돌려준다. 발급(Issuer)과 검증(Inspector)이 같은 서명 계산을 공유한다.
    """

    mac = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256)
    return _b64url_encode(mac.digest())


@dataclass(frozen=True)
class Params:
    """config.yaml 의 jwt 섹션에서 로드한 발급 설정 운반자."""

    secret: bytes
    ttl: timedelta
    issuer: str
    audience: str


def load(settings: JwtSettings) -> Params:
    """공유 설정에서 jwt 섹션을 읽어 검증한다. 오설정(약한/미설정 키, 잘못된 TTL, 미설정
    issuer/audience)은 예외로 던져 부팅 시점에 드러낸다.
    """

    secret = settings.signing_secret
    if secret == "":
        raise ValueError("설정 jwt.signing_secret 가 비어 있음(HS256 서명키 필요)")
    secret_bytes = secret.encode("utf-8")
    if len(secret_bytes) < _MIN_SECRET_BYTES:
        raise ValueError(
            f"설정 jwt.signing_secret 가 너무 짧음(현재 {len(secret_bytes)}바이트, 최소 "
            f"{_MIN_SECRET_BYTES}바이트): 약한 키는 서명 위조 위험"
        )

    ttl = _DEFAULT_TTL
    raw = settings.ttl
    if raw != "":
        try:
            ttl = parse_duration(raw)
        except DurationError as e:
            raise ValueError(f"설정 jwt.ttl 파싱 실패({raw!r}): {e}") from e
    if ttl < _MIN_TTL:
        raise ValueError(
            f"설정 jwt.ttl 는 최소 {_MIN_TTL} 이상이어야 함(현재 {ttl}): 그 미만이면 초 단위 "
            "절삭으로 발급 즉시 만료된 토큰이 나옴"
        )

    issuer = settings.issuer
    if issuer == "":
        raise ValueError("설정 jwt.issuer 가 비어 있음(발급자 식별자 필요)")

    audience = settings.audience
    if audience == "":
        raise ValueError("설정 jwt.audience 가 비어 있음(대상 식별자 필요)")

    return Params(secret=secret_bytes, ttl=ttl, issuer=issuer, audience=audience)


class Issuer:
    """HS256 JWT 로 서버 자체 접근 자격을 발급하는 CredentialIssuer 구현."""

    def __init__(self, params: Params, now: Callable[[], datetime] | None = None) -> None:
        # 주입 시크릿은 방어적으로 복사해 외부 변형으로부터 격리한다.
        self._secret = bytes(params.secret)
        self._ttl = params.ttl
        self._issuer = params.issuer
        self._audience = params.audience
        # now 는 iat/exp 계산에 쓸 현재 시각 소스다. 테스트에서 시각을 고정하려고 주입 가능하게
        # 둔다(도메인 Clock 포트는 코어의 신선도 판단용이라 여기 재사용하지 않고 어댑터 내부의
        # 인코딩 세부로 로컬에 가둔다).
        self._now = now if now is not None else lambda: datetime.now(UTC)

    def issue_credential(self, identity: Identity) -> Credential:
        """검증된 신원에 HS256 JWT 를 발급한다. 발급 과정의 실패는 도메인 거부가 아니라 인프라
        실패이므로 일반 예외로 그대로 전파한다.
        """

        now = self._now()
        exp = now + self._ttl

        iat_unix = int(now.timestamp())
        exp_unix = int(exp.timestamp())

        # 클레임 필드 순서를 고정해 같은 입력이면 항상 같은 바이트가 나온다(결정적 서명).
        claims = {
            "iss": self._issuer,
            "sub": identity.arn,  # 허용 목록 대조 대상이자 안정적 주체 식별자.
            "aud": self._audience,
            "iat": iat_unix,
            "exp": exp_unix,  # exp = iat + TTL.
            "jti": _new_jti(),  # 토큰 고유 id. 추적/재전송 대비.
            "account": identity.account,  # 감사/로그용 부가 정보.
            "user_id": identity.user_id,  # 감사/로그용 부가 정보.
        }
        payload_seg = _b64url_encode(
            json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )

        signing_input = _HEADER_SEGMENT + "." + payload_seg
        token = signing_input + "." + _sign_with(self._secret, signing_input)

        # expires_at 은 토큰 exp 클레임과 같은 초 단위로 맞춰, 반환값과 토큰이 어긋나지 않게 한다.
        return Credential(token=token, expires_at=datetime.fromtimestamp(exp_unix, UTC))


class Inspector:
    """서버가 발급한 HS256 JWT 의 서명/구조를 검증하는 TokenInspector 구현. 발급과 같은 소재를
    쓰므로 형식이 어긋날 여지가 없다.
    """

    def __init__(self, params: Params) -> None:
        self._secret = bytes(params.secret)

    def inspect(self, token: str) -> VerifiedToken:
        """토큰의 3 세그먼트 구조, 헤더(alg=HS256/typ=JWT), HS256 서명을 검증하고 클레임을
        돌려준다. 무효 토큰은 VerificationRejected 로 던진다(수신 어댑터가 401 로 매핑). 만료/
        발급자/대상 판단은 여기서 하지 않고 코어(VerifyService)가 맡는다.
        """

        # 정확히 3 세그먼트여야 한다. 잘린 토큰/세그먼트 수 오류를 거른다.
        parts = token.split(".")
        if len(parts) != 3:
            raise VerificationRejected("토큰 세그먼트 수가 3이 아님")

        # 헤더 세그먼트는 발급 고정값과 정확히 일치해야 한다. 이 한 번의 비교로 alg=HS256 과
        # typ=JWT 를 강제해, alg 변조(예: none/RS256 시도)를 원천 차단한다.
        if parts[0] != _HEADER_SEGMENT:
            raise VerificationRejected("헤더가 HS256/JWT 고정값과 일치하지 않음")

        # 서명 재계산 후 상수시간 비교. 같은 시크릿/알고리즘으로 header.payload 서명을 다시 만들어
        # 토큰의 서명 세그먼트와 비교한다(타이밍 공격 완화). base64 인코딩 형태로 비교하므로,
        # 서명 세그먼트가 잘못된 base64 이거나 길이가 달라도 불일치로 거부된다.
        signing_input = parts[0] + "." + parts[1]
        expected_sig = _sign_with(self._secret, signing_input)
        if not hmac.compare_digest(expected_sig, parts[2]):
            raise VerificationRejected("서명이 일치하지 않음")

        # 페이로드를 디코드해 클레임으로 되살린다. 서명이 검증됐어도 형식 불량은 무효로 본다.
        try:
            payload = _b64url_decode(parts[1])
        except ValueError:
            # binascii.Error 는 ValueError 의 하위 클래스라 함께 잡힌다.
            raise VerificationRejected("페이로드 base64url 디코드 실패") from None
        try:
            c = json.loads(payload)
        except json.JSONDecodeError:
            raise VerificationRejected("페이로드 JSON 파싱 실패") from None
        if not isinstance(c, dict):
            raise VerificationRejected("페이로드 JSON 파싱 실패")

        # 시각 클레임은 초 단위 Unix 시각을 UTC datetime 으로 되살린다(발급의 초 단위 절삭과 대칭).
        return VerifiedToken(
            issuer=str(c.get("iss", "")),
            subject=str(c.get("sub", "")),
            audience=str(c.get("aud", "")),
            expires_at=datetime.fromtimestamp(int(c.get("exp", 0)), UTC),
            issued_at=datetime.fromtimestamp(int(c.get("iat", 0)), UTC),
            jti=str(c.get("jti", "")),
            account=str(c.get("account", "")),
            user_id=str(c.get("user_id", "")),
        )


class _VerifyPolicy:
    """발급 설정(jwt 섹션)의 iss/aud 기대값을 코어에 노출하는 VerifyPolicy 구현."""

    def __init__(self, issuer: str, audience: str) -> None:
        self._issuer = issuer
        self._audience = audience

    def expected_issuer(self) -> str:
        return self._issuer

    def expected_audience(self) -> str:
        return self._audience


def new(params: Params, now: Callable[[], datetime] | None = None) -> Issuer:
    """로드/검증된 Params 로 Issuer 를 만든다."""

    return Issuer(params, now=now)


def new_inspector(params: Params) -> Inspector:
    """로드/검증된 Params 로 Inspector 를 만든다."""

    return Inspector(params)


def new_verify_policy(params: Params) -> VerifyPolicy:
    """로드/검증된 Params 의 issuer/audience 로 VerifyPolicy 를 만든다."""

    return _VerifyPolicy(params.issuer, params.audience)


def _new_jti() -> str:
    """16바이트 난수를 base64url(no pad)로 인코딩한 토큰 고유 id 를 만든다."""

    return _b64url_encode(secrets.token_bytes(16))


def _conforms_issuer(i: Issuer) -> CredentialIssuer:
    """컴파일타임 포트 준수 확인: Issuer 가 CredentialIssuer 를 만족하는지 mypy 가 검사한다."""

    return i


def _conforms_inspector(i: Inspector) -> TokenInspector:
    """컴파일타임 포트 준수 확인: Inspector 가 TokenInspector 를 만족하는지 mypy 가 검사한다."""

    return i
