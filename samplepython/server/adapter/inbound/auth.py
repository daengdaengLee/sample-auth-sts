"""/auth 수신 어댑터. 서명된 GetCallerIdentity 요청(JSON 엔벨로프)을 파싱해 인바운드 포트로
넘기고, 결과를 HTTP 로 매핑한다.

도메인 호출 전에 엔벨로프 파싱과 증명 형태 판별/사전검증을 먼저 하고, 통과한 값만 공통으로
코어에 넘긴다. 형태 판별은 Authorization 헤더(헤더 기반) 대 X-Amz-Algorithm 쿼리(presigned)로
가른다.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

from server.adapter.inbound.http_util import ClientError
from server.domain.errors import (
    RejectionReason,
    as_rejection,
    as_verification_rejected,
)
from server.domain.ports import Authenticator
from server.domain.types import (
    AuthenticateInput,
    PreservedRequest,
    ProofForm,
    SignedRequest,
)

# SigV4 서명 정보를 싣는 헤더. 여기서 SignedHeaders 목록을 파싱해, 신선도/바인딩 근거 헤더가
# 서명 범위 안에 있는지 검증한다.
_AUTHORIZATION_HEADER = "Authorization"

# 서버 바인딩 값을 싣는 헤더. 클라이언트는 이 헤더를 SigV4 서명 범위(SignedHeaders)에 포함해야
# 하며, 서버는 그 값이 자신만의 고유 기대값과 일치하는지 코어에서 대조한다(혼동된 대리자 완화).
_BINDING_HEADER = "X-Server-Binding"

# SigV4 서명 시각을 싣는 헤더. 헤더 기반에서는 신선도 판단의 근거이며, 위변조를 막으려면 서명
# 범위에 포함돼야 한다. presigned 에서는 같은 이름이 URL 쿼리 파라미터로 실린다.
_AMZ_DATE_HEADER = "X-Amz-Date"

# X-Amz-Date 의 ISO8601 basic 형식(예: 20260708T120000Z). 두 형태가 같은 형식을 쓴다.
_AMZ_DATE_FORMAT = "%Y%m%dT%H%M%SZ"

# presigned 형태의 SigV4 정보는 Authorization 헤더가 아니라 URL 쿼리 파라미터로 실린다.
_AMZ_ALGORITHM_PARAM = "X-Amz-Algorithm"
_AMZ_CREDENTIAL_PARAM = "X-Amz-Credential"
_AMZ_DATE_PARAM = "X-Amz-Date"
_AMZ_EXPIRES_PARAM = "X-Amz-Expires"
_AMZ_SIGNED_HEADERS_PARAM = "X-Amz-SignedHeaders"
_AMZ_SIGNATURE_PARAM = "X-Amz-Signature"
_QUERY_ACTION_KEY = "Action"

# 받아들일 X-Amz-Expires 의 상한(초). AWS 도 presigned URL 만료를 최대 7일로 두므로 이를 상한으로
# 삼는다. 서버는 어차피 자체 최대 age 와 교집합(min)을 취하므로 이보다 큰 만료는 의미가 없다.
# 상한 초과는 클램프가 아니라 거부한다(config 검증과 같은 톤). 클라이언트도 같은 상한을 로컬에서
# 거르므로, 정상 클라이언트는 이 서버 거부에 도달하지 않는다. 두 값이 어긋나면 e2e 테스트가 초
# 환산 동일성을 단언한다(그 대조를 위해 export 한다).
MAX_PRESIGN_EXPIRY_SECONDS = 7 * 24 * 60 * 60


@dataclass(frozen=True)
class _ExtractedProof:
    """두 증명 형태(header/presigned)에서 공통으로 뽑아 코어로 넘길 스칼라 묶음."""

    form: ProofForm
    binding: str
    signed_at: datetime
    action: str
    expiry: timedelta  # presigned 만 채운다(header 는 0)


class AuthHandler:
    """/auth 핸들러. 인바운드 포트 Authenticator 를 주입받아 파싱한 서명 요청을 코어로 넘긴다."""

    def __init__(self, auth: Authenticator) -> None:
        self._auth = auth

    def handle(self, payload: object) -> tuple[int, dict[str, str]]:
        """파싱된 JSON 엔벨로프를 받아 (status, body) 를 돌려주는 동기 처리 본체. 스레드풀에서
        실행된다(블로킹 STS 위임을 이벤트 루프 밖으로 보냄).
        """

        try:
            return self._handle(payload)
        except ClientError as e:
            return e.status, {"error": e.code, "message": e.message}

    def _handle(self, payload: object) -> tuple[int, dict[str, str]]:
        req = _parse_auth_request(payload)

        # 서명 대상 바이트를 그대로 되살리려고 base64 로 디코드한다. STS 는 이 바이트에 대해 서명을
        # 재검증하므로, 한 바이트라도 어긋나면 위임이 거절된다.
        try:
            body = base64.standard_b64decode(req.body)
        except (binascii.Error, ValueError) as e:
            raise ClientError(400, "invalid_body", "body 는 base64(표준 인코딩)여야 함") from e

        # 형태 판별 -> 형태별 추출기로 분기한다. Authorization 헤더가 있으면 헤더 기반, 없으면
        # presigned 로 시도한다. presigned 도 아니면(X-Amz-Algorithm 쿼리 부재) 거부한다.
        if _header_values(req.headers, _AUTHORIZATION_HEADER):
            p = _extract_header_form(req, body)
        else:
            p = _extract_presigned_form(req)

        input_ = AuthenticateInput(
            request=SignedRequest(
                form=p.form,
                binding_value=p.binding,
                method=req.method,
                action=p.action,
                signed_at=p.signed_at,
                expiry=p.expiry,
                original=PreservedRequest(
                    method=req.method,
                    url=req.url,
                    header=req.headers,
                    body=body,
                ),
            )
        )

        # 도메인/어댑터가 던진 예외(로컬 거부/무자격/인프라)는 map_error 로 HTTP 상태로 매핑한다.
        # 파싱 단계의 ClientError 와 달리, 여기서부터는 코어 호출 결과이므로 Go writeAuthError 와
        # 같은 매핑을 적용한다.
        try:
            out = self._auth.authenticate(input_)
        except Exception as e:  # noqa: BLE001 - Go writeAuthError 처럼 모든 코어 오류를 매핑한다
            return self.map_error(e)

        return 200, {
            "token": out.credential.token,
            "expires_at": _rfc3339(out.credential.expires_at),
        }

    def map_error(self, err: Exception) -> tuple[int, dict[str, str]]:
        """도메인/어댑터가 던진 예외를 (status, body) 로 매핑한다. 로컬 거부(RejectionError)는
        사유별 4xx 로, 위임 검증 무자격(VerificationRejected)은 401 로, 그 외 인프라 오류는 502 로
        매핑한다.
        """

        re = as_rejection(err)
        if re is not None:
            status = _rejection_status(re.reason)
            return status, {"error": re.reason.value, "message": re.message}

        ve = as_verification_rejected(err)
        if ve is not None:
            return 401, {
                "error": "verification_failed",
                "message": "신원 검증에 실패함(서명 무효/만료 등)",
            }

        # 그 외는 인프라 실패다. 위임 upstream 실패로 보고 502 로 매핑한다.
        return 502, {"error": "upstream_error", "message": "인증 처리 중 인프라 오류"}


@dataclass(frozen=True)
class _AuthRequest:
    """/auth 요청 본문(JSON 엔벨로프). 클라이언트가 SigV4 로 서명한 원본 GetCallerIdentity 요청을
    재구성 없이 그대로 담는다. body 는 서명 대상 바이트를 정확히 보존하려고 base64(표준 인코딩)로
    싣는다.
    """

    method: str
    url: str
    headers: dict[str, list[str]]
    body: str


def _parse_auth_request(payload: object) -> _AuthRequest:
    """JSON 엔벨로프를 _AuthRequest 로 검증/변환한다. 형태가 어긋나면 400 invalid_body 로 거부한다.
    headers 는 dict[str, list[str]] 여야 한다(각 값은 문자열 목록).
    """

    if not isinstance(payload, dict):
        raise ClientError(400, "invalid_body", "요청 본문이 객체가 아님")

    method = payload.get("method")
    url = payload.get("url")
    body = payload.get("body")
    headers_raw = payload.get("headers")

    if not isinstance(method, str) or not isinstance(url, str) or not isinstance(body, str):
        raise ClientError(400, "invalid_body", "method/url/body 는 문자열이어야 함")

    headers: dict[str, list[str]] = {}
    if headers_raw is not None:
        if not isinstance(headers_raw, dict):
            raise ClientError(400, "invalid_body", "headers 는 객체여야 함")
        for k, v in headers_raw.items():
            if not isinstance(k, str) or not isinstance(v, list):
                raise ClientError(400, "invalid_body", "headers 는 문자열->문자열 목록이어야 함")
            values: list[str] = []
            for item in v:
                if not isinstance(item, str):
                    raise ClientError(400, "invalid_body", "headers 값은 문자열 목록이어야 함")
                values.append(item)
            headers[k] = values

    return _AuthRequest(method=method, url=url, headers=headers, body=body)


def _extract_header_form(req: _AuthRequest, body: bytes) -> _ExtractedProof:
    """헤더 기반 서명(Authorization 헤더에 SignedHeaders)에서 신선도/바인딩 근거를 뽑는다. 서명
    밖에서 주입된 헤더는 STS 가 서명 검증에서 무시하므로, X-Amz-Date/바인딩 헤더가 SignedHeaders
    목록 안에 있는지 함께 확인해 위변조 우회를 막는다.
    """

    # 보안 관련 헤더는 정확히 1개 값만 허용한다. 대소문자만 다른 중복 키는 서로 다른 JSON 키로
    # 파싱되어 비결정적이 되므로, 다중 값을 아예 거부한다.
    authz_vals = _header_values(req.headers, _AUTHORIZATION_HEADER)
    if len(authz_vals) != 1:
        raise ClientError(400, "invalid_signature", "Authorization 헤더가 없거나 값이 2개 이상임")

    # SigV4 SignedHeaders 목록을 뽑는다. 서명 밖에서 주입된 헤더는 STS 가 무시하므로, 신선도/
    # 바인딩 근거 헤더가 이 목록 안에 있는지 확인해 위변조 우회를 막는다.
    signed = _signed_header_set(authz_vals[0])
    if not signed:
        raise ClientError(
            400, "invalid_signature", "Authorization 헤더의 SignedHeaders 를 해석할 수 없음"
        )

    # 신선도 근거(signed_at)는 서명된 X-Amz-Date 에서만 얻는다.
    raw_date = _single_signed_value(req.headers, signed, _AMZ_DATE_HEADER)
    if raw_date is None:
        raise ClientError(
            400,
            "invalid_signature",
            "X-Amz-Date 가 없거나 값이 2개 이상이거나 서명 범위에 포함되지 않음",
        )
    signed_at = _parse_amz_date(raw_date)

    # 바인딩 헤더가 없거나(또는 다중이거나) 서명 범위 밖이면, 이 증명이 이 서버로 바인딩됐다고 볼
    # 수 없다(혼동된 대리자). 값 대조(코어) 이전에 여기서 거부한다.
    binding = _signed_binding(req.headers, signed)

    return _ExtractedProof(
        form=ProofForm.HEADER,
        binding=binding,
        signed_at=signed_at,
        action=_action_from_form(body),
        expiry=timedelta(0),
    )


def _extract_presigned_form(req: _AuthRequest) -> _ExtractedProof:
    """pre-signed URL 형태에서 신선도/만료/바인딩 근거를 URL 쿼리에서 뽑는다. Authorization 헤더
    대신 X-Amz-SignedHeaders 를 서명 범위로, X-Amz-Date + X-Amz-Expires 를 신선도/만료 근거로,
    X-Amz-Algorithm/Credential/Signature 존재를 확인한다.
    """

    try:
        parts = urlsplit(req.url)
    except ValueError as e:
        raise ClientError(400, "invalid_signature", "presigned URL 을 해석할 수 없음") from e
    q = parse_qs(parts.query, keep_blank_values=True)

    # 형태 게이트: presigned 는 URL 쿼리에 X-Amz-Algorithm 을 싣는다. Authorization 헤더가 없는데
    # 이마저 없으면 지원하는 두 형태 어디에도 해당하지 않으므로 형태 판별 불가로 거부한다.
    if _AMZ_ALGORITHM_PARAM not in q:
        raise ClientError(
            400,
            "invalid_signature",
            "증명 형태를 판별할 수 없음(Authorization 헤더도 presigned 쿼리도 없음)",
        )

    # SigV4 쿼리 서명의 필수 파라미터가 각각 정확히 1개로 존재하는지 확인한다(파라미터 오염 방지).
    for name in (_AMZ_ALGORITHM_PARAM, _AMZ_CREDENTIAL_PARAM, _AMZ_SIGNATURE_PARAM):
        if len(q.get(name, [])) != 1:
            raise ClientError(
                400,
                "invalid_signature",
                "presigned SigV4 쿼리 파라미터가 없거나 값이 2개 이상임",
            )

    # 서명 범위(SignedHeaders)는 X-Amz-SignedHeaders 쿼리에서 얻는다.
    raw_signed_headers = _single_query_value(q, _AMZ_SIGNED_HEADERS_PARAM)
    if raw_signed_headers is None:
        raise ClientError(400, "invalid_signature", "X-Amz-SignedHeaders 가 없거나 값이 2개 이상임")
    signed = _parse_signed_header_list(raw_signed_headers)
    if not signed:
        raise ClientError(400, "invalid_signature", "X-Amz-SignedHeaders 를 해석할 수 없음")

    # 신선도 근거(signed_at)는 X-Amz-Date 쿼리에서 얻는다.
    raw_date = _single_query_value(q, _AMZ_DATE_PARAM)
    if raw_date is None:
        raise ClientError(400, "invalid_signature", "X-Amz-Date 가 없거나 값이 2개 이상임")
    signed_at = _parse_amz_date(raw_date)

    # 만료 근거(expiry)는 X-Amz-Expires 쿼리에서 얻는다(초 단위 양의 정수, 상한 이내).
    raw_expires = _single_query_value(q, _AMZ_EXPIRES_PARAM)
    if raw_expires is None:
        raise ClientError(400, "invalid_signature", "X-Amz-Expires 가 없거나 값이 2개 이상임")
    try:
        exp_secs = int(raw_expires)
    except ValueError:
        exp_secs = -1
    if exp_secs <= 0 or exp_secs > MAX_PRESIGN_EXPIRY_SECONDS:
        raise ClientError(
            400, "invalid_signature", "X-Amz-Expires 는 양의 정수(초)이고 상한 이내여야 함"
        )

    # 바인딩 헤더가 실제 헤더로 존재하고 동시에 X-Amz-SignedHeaders 목록에 있어야 통과한다.
    binding = _signed_binding(req.headers, signed)

    # Action 은 헤더 기반이 폼 바디에서 뽑는 것과 대칭으로 URL 쿼리에서 뽑는다. 정확히 1개일 때만
    # 채우고, 부재/중복이면 빈 값으로 두어 코어가 invalid_shape 로 거르게 한다.
    action = ""
    action_vals = q.get(_QUERY_ACTION_KEY, [])
    if len(action_vals) == 1:
        action = action_vals[0]

    return _ExtractedProof(
        form=ProofForm.PRESIGNED,
        binding=binding,
        signed_at=signed_at,
        action=action,
        expiry=timedelta(seconds=exp_secs),
    )


def _rejection_status(reason: RejectionReason) -> int:
    """로컬 거부 사유를 HTTP 상태로 매핑한다. 형태 불량은 400, 신선도 초과는 401 이다. 그 외
    (바인딩 불일치/허용되지 않은 ARN 등)는 안전하게 거부(403)로 매핑한다.
    """

    if reason == RejectionReason.INVALID_SHAPE:
        return 400
    if reason == RejectionReason.STALE:
        return 401
    return 403


def _parse_amz_date(raw: str) -> datetime:
    """X-Amz-Date(ISO8601 basic)를 tz-aware UTC datetime 으로 파싱한다. 형식이 틀리면 400."""

    try:
        return datetime.strptime(raw, _AMZ_DATE_FORMAT).replace(tzinfo=UTC)
    except ValueError as e:
        raise ClientError(400, "invalid_signature", "X-Amz-Date 형식이 올바르지 않음") from e


def _header_values(headers: dict[str, list[str]], name: str) -> list[str]:
    """헤더 맵에서 name 과 대소문자 무시로 일치하는 모든 키의 값을 하나로 모아 돌려준다.
    대소문자만 다른 중복 키까지 합쳐, 보안 관련 헤더의 "정확히 1개" 검사가 중복 주입을 놓치지
    않게 한다.
    """

    vals: list[str] = []
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            vals.extend(v)
    return vals


def _single_signed_value(headers: dict[str, list[str]], signed: set[str], name: str) -> str | None:
    """name 헤더가 정확히 1개 값이고 그 헤더가 SigV4 SignedHeaders 목록에 포함됐는지 확인해 그
    값을 돌려준다. 조건을 못 맞추면 None 이다. 서명 밖 다중값/주입 헤더를 신선도/바인딩 근거로
    쓰지 않도록 막는 공통 검사다.
    """

    vals = _header_values(headers, name)
    if len(vals) != 1 or name.lower() not in signed:
        return None
    return vals[0]


def _single_query_value(q: dict[str, list[str]], key: str) -> str | None:
    """쿼리 파라미터 key 가 정확히 1개 값일 때 그 값을 돌려준다. 부재/다중이면 None."""

    vals = q.get(key, [])
    if len(vals) != 1:
        return None
    return vals[0]


def _signed_binding(headers: dict[str, list[str]], signed: set[str]) -> str:
    """바인딩 헤더가 실제 헤더로 정확히 1개 존재하면서 SigV4 서명 범위(SignedHeaders)에 포함되는지
    확인해 그 값을 돌려준다. 두 형태가 공유하는 혼동된 대리자 검사로, 서명 범위 밖 바인딩은 전달
    과정에서 값이 바뀌어도 서명이 깨지지 않아 완화가 무력화되므로 거부한다(403).
    """

    binding = _single_signed_value(headers, signed, _BINDING_HEADER)
    if binding is None:
        raise ClientError(
            403,
            "binding_not_signed",
            "서버 바인딩 헤더가 없거나 값이 2개 이상이거나 서명 범위에 포함되지 않음",
        )
    return binding


def _action_from_form(body: bytes) -> str:
    """POST 폼 바디에서 Action 파라미터를 뽑는다(헤더 기반 경로용). 정확히 1개일 때만 채우고,
    부재/중복(파라미터 오염)이면 빈 값을 돌려주어 코어가 invalid_shape 로 거르게 한다.
    """

    try:
        form = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except (UnicodeDecodeError, ValueError):
        return ""
    vals = form.get(_QUERY_ACTION_KEY, [])
    if len(vals) == 1:
        return vals[0]
    return ""


def _signed_header_set(authorization: str) -> set[str]:
    """SigV4 Authorization 헤더 값에서 SignedHeaders 구간을 찾아, 세미콜론으로 구분된 헤더 이름들을
    소문자 집합으로 돌려준다. 찾지 못하거나 비면 빈 집합이다. 형식 예:
    "AWS4-HMAC-SHA256 Credential=..., SignedHeaders=host;x-amz-date;x-server-binding, Signature=..."
    """

    marker = "SignedHeaders="
    i = authorization.find(marker)
    if i < 0:
        return set()
    rest = authorization[i + len(marker) :]
    # SignedHeaders 값은 다음 콤마(", Signature=...") 전까지다.
    j = rest.find(",")
    if j >= 0:
        rest = rest[:j]
    return _parse_signed_header_list(rest)


def _parse_signed_header_list(value: str) -> set[str]:
    """세미콜론으로 구분된 SignedHeaders 목록을 소문자 집합으로 돌려준다. 비면 빈 집합이다."""

    return {name.strip().lower() for name in value.split(";") if name.strip()}


def _rfc3339(dt: datetime) -> str:
    """datetime 을 RFC3339(UTC 는 'Z' 접미사)로 직렬화한다. Go time.RFC3339 와 바이트 단위로
    맞춘다(Python isoformat 의 '+00:00' 대신 'Z').
    """

    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
