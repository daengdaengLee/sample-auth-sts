"""STS 신원 검증 어댑터. 도메인 IdentityVerifier 아웃바운드 포트를 실제 AWS STS 위임으로
구현한다(5~6단계). 코어가 보존해 넘긴 원본 서명 요청을 재구성 없이 그대로 STS 로 전달하고,
돌려받은 GetCallerIdentity 응답에서 호출자 신원(ARN 등)을 뽑아 코어로 돌려준다.

위임 대상이 허용 목록의 진짜 STS 엔드포인트인지 강제하는 5단계(STS 엔드포인트 신뢰)는 이
어댑터가 경계에서 책임진다. AWS SDK 없이 httpx + 표준 XML 파서만 쓴다. SigV4 서명은 STS 가
검증하며, 이 어댑터는 서명을 해석하지 않고 서명된 요청을 바이트 그대로 중개한다.
"""

from __future__ import annotations

import ssl
from urllib.parse import urlsplit
from xml.etree import ElementTree

import httpx

from server.domain.errors import VerificationRejected
from server.domain.ports import IdentityVerifier
from server.domain.types import Identity, PreservedRequest
from server.internal.config import StsSettings
from shared.httpread import read_capped

# 재구성 시 요청 host 로 옮겨 실어야 하는 헤더 이름. httpx 는 URL 에서 Host 를 재계산하므로,
# 보존된 Host 를 명시 헤더로 실어 서명 범위와 일치시킨다.
_HOST_HEADER = "Host"

# STS 응답 본문을 읽을 최대 바이트. GetCallerIdentity 응답은 작으므로(수백 바이트) 넉넉히 1 MiB
# 로 두고, 이를 넘으면 인프라 오류로 본다. 상한이 없으면 비정상/악의적 엔드포인트가 거대한
# 본문으로 메모리를 고갈시킬 수 있다.
_MAX_RESPONSE_BYTES = 1 << 20


class VerificationError(VerificationRejected):
    """STS 가 호출자 신원을 확인해 주지 못했음을(또는 위임 자체를 거절했음을) 나타낸다. 서명
    무효/만료 같은 STS 의 클라이언트측 거절(4xx)과 위임 대상이 허용 목록의 진짜 STS 엔드포인트가
    아닌 경우가 여기 해당한다. VerificationRejected 를 상속해, 수신 어댑터가 이 어댑터 패키지에
    의존하지 않고 도메인 타입만으로 무자격(4xx) 대 인프라 실패(5xx)를 가른다.

    STS 고유 진단 필드(http_status/sts_code/sts_message)를 담아 어댑터 안에서의 로그/디버깅에
    쓴다.
    """

    def __init__(
        self,
        reason: str,
        http_status: int = 0,
        sts_code: str = "",
        sts_message: str = "",
    ) -> None:
        self.http_status = http_status
        self.sts_code = sts_code
        self.sts_message = sts_message
        parts = [f"STS 신원 검증 실패({reason})"]
        if http_status != 0:
            parts.append(f" status={http_status}")
        if sts_code != "":
            parts.append(f" code={sts_code}")
        if sts_message != "":
            parts.append(f" message={sts_message}")
        super().__init__("".join(parts))
        # 상위(VerificationRejected)의 reason 은 메시지가 되므로, 짧은 사유를 따로 보존한다.
        self.reason = reason


def _is_transient_code(code: str) -> bool:
    """STS 에러 코드가 스로틀링/레이트리밋 같은 일시 상태인지 판단한다. 이런 요청은 서명이
    무효한 게 아니라 잠시 뒤 재시도하면 통과할 수 있으므로, 4xx 라도 무자격이 아니라 인프라
    실패(재시도 대상)로 갈라야 한다.

    "exceeded" 통짜가 아니라 "limitexceeded" 로 맞춰, 레이트/대역 한도 계열만 잡고 비스로틀
    "...Exceeded" 코드를 일시로 오강등하지 않게 한다. 대소문자를 무시한다.
    """

    c = code.lower()
    return "throttl" in c or "limitexceeded" in c or "toomanyrequests" in c


def _local_name(tag: str) -> str:
    """XML 태그에서 네임스페이스를 뗀 로컬 이름을 돌려준다(예: '{ns}Arn' -> 'Arn')."""

    return tag.rsplit("}", 1)[-1]


def _find_text(root: ElementTree.Element, path: list[str]) -> str:
    """네임스페이스를 무시하고 로컬 이름 경로로 자식 요소를 따라가 텍스트를 돌려준다. 없으면
    빈 문자열이다.
    """

    node: ElementTree.Element | None = root
    for want in path:
        if node is None:
            return ""
        found: ElementTree.Element | None = None
        for child in node:
            if _local_name(child.tag) == want:
                found = child
                break
        node = found
    if node is None or node.text is None:
        return ""
    return node.text


def _normalize_endpoint(raw: str) -> str:
    """URL 문자열에서 비교용 엔드포인트 키(scheme://host:port)를 뽑는다. 경로/쿼리는 무시한다.
    https 가 아니거나 host 가 없으면 빈 문자열을 돌려준다(무효). https 만 허용하는 것은 평문
    다운그레이드를 막기 위해서다. host 는 소문자화하고 후행 점 하나를 떼며, 포트가 비면
    기본값(443)으로 채운다.
    """

    try:
        u = urlsplit(raw.strip())
    except ValueError:
        return ""
    if u.scheme.lower() != "https":
        return ""

    hostname = u.hostname
    if hostname is None or hostname == "":
        return ""
    # 후행 점 하나만 뗀다(Go TrimSuffix 대응). rstrip 은 여러 점을 지워 정규화가 어긋난다.
    host = hostname.lower()
    if host.endswith("."):
        host = host[:-1]
    if host == "":
        return ""

    port = u.port if u.port is not None else 443

    # IPv6 host 는 대괄호로 감싼다.
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}:{port}"


class Verifier:
    """허용된 STS 엔드포인트로 원본 서명 요청을 위임해 호출자 신원을 돌려받는 IdentityVerifier
    구현이다.
    """

    def __init__(self, client: httpx.Client, allowed_endpoints: list[str]) -> None:
        self._client = client
        self._allowed = {key for ep in allowed_endpoints if (key := _normalize_endpoint(ep)) != ""}

    def allowed_endpoint_count(self) -> int:
        """정규화를 통과해 실제로 허용되는 STS 엔드포인트 수를 돌려준다."""

        return len(self._allowed)

    def verify_identity(self, req: PreservedRequest) -> Identity:
        """보존된 원본 서명 요청을 허용된 STS 엔드포인트로 그대로 전달하고, 돌려받은
        GetCallerIdentity 응답에서 호출자 신원을 뽑아 반환한다. 위임 대상이 허용 목록에 없거나
        STS 가 요청을 거절하면 VerificationError 를, 전송/파싱 같은 인프라 실패는 일반 예외를
        던진다.
        """

        # 5단계. STS 엔드포인트 신뢰: 위임 대상 엔드포인트가 허용 목록에 든 진짜 STS 인지
        # 강제한다. 어긋나면 HTTP 호출 없이 즉시 거부해, 가짜 엔드포인트로의 전달을 막는다.
        endpoint = _normalize_endpoint(req.url)
        if endpoint == "":
            raise VerificationError("위임 대상 URL 을 해석할 수 없음")
        if endpoint not in self._allowed:
            raise VerificationError("위임 대상이 STS 엔드포인트 허용 목록에 없음")

        headers = _build_headers(req)

        # 6단계. STS 위임: 서명된 요청을 바이트 그대로 전달한다. 전송 실패는 인프라 실패다.
        # 리다이렉트는 끄므로(client 설정) 3xx 가 그대로 돌아온다. Host 헤더는 headers 에 명시로
        # 실어 httpx 가 URL 로 재계산하지 않고 서명된 값을 그대로 보내게 한다(SNI 는 URL host 에서
        # 파생되므로 별도 지정하지 않는다).
        #
        # 스트리밍으로 받아 본문 읽기 자체를 상한으로 제한한다. request() 로 받으면 httpx 가 본문
        # 전체를 먼저 메모리에 올린 뒤라 사후 슬라이스로는 메모리 고갈을 못 막는다. 상한을 넘는
        # 순간 순회를 멈춰 실제 읽기를 상한 + 한 청크 이내로 묶는다(Go io.LimitReader 대응).
        try:
            with self._client.stream(
                req.method,
                req.url,
                content=req.body,
                headers=headers,
            ) as resp:
                status = resp.status_code
                location = resp.headers.get("Location", "")
                body, oversized = read_capped(resp, _MAX_RESPONSE_BYTES)
        except httpx.HTTPError as e:
            raise RuntimeError(f"STS 위임 요청 전송 실패: {e}") from e

        # 리다이렉트를 끄므로 3xx 가 여기까지 온다. STS 는 정상적으로 리다이렉트하지 않으니,
        # 따라가지 않은 3xx 는 무자격이 아니라 인프라 오류(예기치 않은 응답)다.
        if 300 <= status < 400:
            raise RuntimeError(
                f"STS 가 예기치 않게 리다이렉트함(status={status}, location={location!r})"
            )

        if status != 200:
            raise _classify_error_response(status, body)

        # 성공 응답은 본문을 XML 파싱하므로, 상한을 넘었다면(신뢰 불가) 인프라 오류로 본다.
        if oversized:
            raise RuntimeError(f"STS 응답 본문이 상한({_MAX_RESPONSE_BYTES} bytes)을 초과함")

        try:
            root = ElementTree.fromstring(body)
        except ElementTree.ParseError as e:
            raise RuntimeError(f"STS 응답 XML 파싱 실패: {e}") from e

        arn = _find_text(root, ["GetCallerIdentityResult", "Arn"])
        if arn == "":
            raise RuntimeError("STS 응답에 ARN 이 없음")
        account = _find_text(root, ["GetCallerIdentityResult", "Account"])
        user_id = _find_text(root, ["GetCallerIdentityResult", "UserId"])

        return Identity(arn=arn, account=account, user_id=user_id)


def _build_headers(req: PreservedRequest) -> dict[str, str]:
    """보존된 원본 요청 헤더를 httpx 용으로 재구성한다. SigV4 서명을 깨지 않도록 헤더를 변형
    없이 그대로 옮긴다. Host 헤더도 명시로 실어 httpx 가 URL 로 재계산하지 않고 서명된 값을
    보내게 한다. 같은 이름의 여러 값은 콤마로 합친다(HTTP 관례).
    """

    headers: dict[str, str] = {}
    host = ""
    for name, values in req.header.items():
        if name.lower() == _HOST_HEADER.lower():
            if values:
                host = values[0]
            continue
        if values:
            headers[name] = ", ".join(values)
    if host:
        headers[_HOST_HEADER] = host
    return headers


def _classify_error_response(status: int, body: bytes) -> Exception:
    """STS 비200(3xx 제외) 응답을 검증 실패(무자격)와 인프라 실패(재시도 대상)로 가른다.
    ErrorResponse XML 이 있으면 코드/메시지를 담는다.

    4xx 라도 스로틀링/레이트리밋이나 HTTP 429 는 서명이 무효한 게 아니라 잠시 뒤 재시도하면
    통과할 수 있는 일시 상태이므로 인프라 실패로 돌린다. 그 외 4xx(서명 무효/만료 등)만 무자격으로
    본다. 5xx 는 인프라 실패다.
    """

    code = ""
    message = ""
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        root = None  # 파싱 실패해도 상태코드로는 분류할 수 있으므로 무시한다.
    if root is not None:
        code = _find_text(root, ["Error", "Code"])
        message = _find_text(root, ["Error", "Message"])

    transient = status == 429 or _is_transient_code(code)

    if 400 <= status < 500 and not transient:
        return VerificationError(
            "STS 가 서명된 요청을 거절함",
            http_status=status,
            sts_code=code,
            sts_message=message,
        )

    if code != "":
        return RuntimeError(f"STS 위임 실패(status={status} code={code}): {message}")
    return RuntimeError(f"STS 위임 실패(status={status})")


def load_allowed_endpoints(settings: StsSettings) -> list[str]:
    """공유 설정에서 STS 엔드포인트 허용 목록을 쉼표로 갈라, 앞뒤 공백을 다듬고 빈 항목을 버린
    정돈된 목록으로 돌려준다.
    """

    return [ep.strip() for ep in settings.endpoint_allowlist.split(",") if ep.strip()]


def load_ca_file(settings: StsSettings) -> str:
    """공유 설정에서 데모 전용 CA 파일 경로를 읽어 앞뒤 공백을 다듬어 돌려준다. 미설정/빈 값이면
    빈 문자열이다.
    """

    return settings.ca_file.strip()


def build_client(timeout: float, ca_file: str = "") -> httpx.Client:
    """STS 위임에 쓸 httpx 클라이언트를 만든다. 리다이렉트는 끄고(허용 목록 우회 방지), 타임아웃을
    건다. ca_file 이 지정되면 그 CA 만 배타적으로 신뢰한다(데모 전용, Go RootCAs 교체와 동일
    의미). InsecureSkipVerify 대응(검증 끄기)은 절대 쓰지 않는다.
    """

    verify: ssl.SSLContext | bool
    if ca_file != "":
        # cafile 을 주면 시스템 신뢰 저장소를 로드하지 않고 그 CA 만 신뢰한다(배타적 대체).
        # 파일이 없거나 유효한 인증서가 아니면 raw ssl/OS 오류 대신 명확한 메시지로 부팅을
        # 실패시킨다(Go LoadCAPool 의 명확한 에러 대응).
        try:
            verify = ssl.create_default_context(cafile=ca_file)
        except (OSError, ssl.SSLError) as e:
            raise ValueError(f"STS CA 파일({ca_file}) 로드 실패: {e}") from e
    else:
        verify = True
    return httpx.Client(timeout=timeout, follow_redirects=False, verify=verify)


def new(client: httpx.Client, allowed_endpoints: list[str]) -> Verifier:
    """HTTP 클라이언트와 허용할 STS 엔드포인트 목록을 주입해 Verifier 를 만든다."""

    return Verifier(client, allowed_endpoints)


def new_verifier(client: httpx.Client, settings: StsSettings) -> Verifier:
    """공유 설정에서 허용 엔드포인트를 읽어 Verifier 를 만들고, 정규화를 통과한 유효 엔드포인트가
    하나도 없으면 예외를 던진다. "떠 있지만 모든 /auth 가 실패하는" 상태를 어댑터 경계에서 막는다.
    """

    verifier = new(client, load_allowed_endpoints(settings))
    if verifier.allowed_endpoint_count() == 0:
        raise ValueError("설정 sts.endpoint_allowlist 에 유효한 https STS 엔드포인트가 하나도 없음")
    return verifier


def _conforms(v: Verifier) -> IdentityVerifier:
    """컴파일타임 포트 준수 확인: Verifier 가 IdentityVerifier 를 만족하는지 mypy 가 검사한다
    (Go 의 `var _ IdentityVerifier = (*Verifier)(nil)` 대응). 실행되지 않는다.
    """

    return v
