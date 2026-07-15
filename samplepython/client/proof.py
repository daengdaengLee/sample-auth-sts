"""증명 생성(README "클라이언트 > 증명 생성 및 전송"의 3~4단계). 보유한 AWS 자격증명으로
GetCallerIdentity 요청에 SigV4 서명을 만들고, 서버 바인딩 헤더를 서명 범위(SignedHeaders)에
포함한 뒤 서버 /auth 가 받는 JSON 엔벨로프로 직렬화한다. 시크릿 키는 서명에만 쓰이고 요청/
엔벨로프에는 담기지 않는다(PoP).

서명 자체는 검증된 구현(botocore 의 SigV4Auth/SigV4QueryAuth)에 위임한다. botocore 는 서명 시각을
인자로 받지 않고 항상 현재 시각을 쓰므로(운영에선 항상 now 라 무해), 이 함수들은 signed_at 을
입력으로 받지 않는다. 결정적 서명이 필요한 테스트는 botocore.auth 의 시각 소스를 freeze 한다.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from botocore.auth import SigV4Auth, SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from client.envelope import Envelope, envelope_from_request, presigned_envelope

# SigV4 서명에 쓰는 AWS 서비스 이름. GetCallerIdentity 는 STS 호출이다.
_SERVICE = "sts"

# 서버 바인딩 값을 싣는 헤더 이름. 서버 수신 어댑터의 bindingHeader 와 반드시 같아야 한다. 이
# 헤더는 서명 전에 설정해 SignedHeaders 에 들어가야 의미가 있다(서명 범위 밖 첨부는 위변조로
# 무력화됨).
_BINDING_HEADER = "X-Server-Binding"

_CONTENT_TYPE_HEADER = "Content-Type"
_CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"

# 서명 대상 GetCallerIdentity 요청 본문. 서버는 이 바디에서 Action 이 정확히 1개
# (GetCallerIdentity)인지 확인한다(전달 요청 형태 검증).
_FORM_BODY = "Action=GetCallerIdentity&Version=2011-06-15"

_ACTION_KEY = "Action"
_VERSION_KEY = "Version"
_ACTION_VALUE = "GetCallerIdentity"
_VERSION_VALUE = "2011-06-15"


def build_proof(
    credentials: Credentials,
    endpoint: str,
    region: str,
    binding_value: str,
) -> Envelope:
    """헤더 기반 SigV4 서명을 만들고, 서버 바인딩 헤더를 서명 범위에 포함한 엔벨로프를 돌려준다.

    1. GetCallerIdentity POST 요청을 만들고 Content-Type 과 X-Server-Binding 을 서명 전에 설정한다
       (서명 범위에 들어가도록).
    2. SigV4Auth.add_auth 로 Authorization 과 X-Amz-Date(및 임시 자격증명 시 X-Amz-Security-Token)
       를 채운다. botocore 는 blacklist 외 모든 헤더를 서명하므로 위 두 헤더와 host 가 서명 범위에
       들어가고, payload 해시는 본문 sha256 이다.
    3. 서명된 요청을 엔벨로프로 직렬화한다(Host 명시 추가, 본문 base64 표준 인코딩).
    """

    body = _FORM_BODY.encode("ascii")
    req = AWSRequest(
        method="POST",
        url=endpoint,
        data=body,
        headers={
            _CONTENT_TYPE_HEADER: _CONTENT_TYPE_FORM,
            _BINDING_HEADER: binding_value,
        },
    )
    SigV4Auth(credentials, _SERVICE, region).add_auth(req)

    host = urlsplit(endpoint).netloc
    return envelope_from_request(dict(req.headers.items()), host, endpoint, body)


def build_presigned_proof(
    credentials: Credentials,
    endpoint: str,
    region: str,
    binding_value: str,
    expiry_seconds: int,
) -> Envelope:
    """pre-signed URL(SigV4 쿼리) 서명을 만들고, 서버 바인딩 헤더를 서명 범위에 포함한 엔벨로프를
    돌려준다(AWS IAM Authenticator 방식).

    1. Action/Version 을 쿼리에 넣은 GET 요청을 만든다. X-Amz-Expires 는 botocore 의
       SigV4QueryAuth(expires=)가 자동으로 쿼리에 넣으므로 여기서 미리 넣지 않는다(중복 방지 --
       aws-sdk-go-v2 와 달리 botocore 는 만료를 스스로 싣는다).
    2. X-Server-Binding 을 서명 전에 헤더로 설정한다. X-Amz- 접두가 아니라 쿼리로 hoisting 되지
       않고 서명된 canonical 헤더로 남아 X-Amz-SignedHeaders 에 들어간다(혼동된 대리자 완화). 실제
       헤더 값도 엔벨로프에 함께 실어 보낸다.
    3. SigV4QueryAuth.add_auth 가 서명된 URL(쿼리에 SigV4 정보 포함)을 req.url 에 채운다. 임시
       자격증명이면 X-Amz-Security-Token 도 쿼리로 hoisting 된다.
    """

    parts = urlsplit(endpoint)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append((_ACTION_KEY, _ACTION_VALUE))
    query.append((_VERSION_KEY, _VERSION_VALUE))
    url_with_query = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )

    req = AWSRequest(
        method="GET",
        url=url_with_query,
        headers={_BINDING_HEADER: binding_value},
    )
    SigV4QueryAuth(credentials, _SERVICE, region, expires=expiry_seconds).add_auth(req)

    signed_url = req.url
    host = urlsplit(signed_url).netloc
    return presigned_envelope(signed_url, host, binding_value)
