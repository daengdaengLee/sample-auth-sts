"""클라이언트 설정 로드(README "클라이언트 > 증명 생성 및 전송"의 1단계). 절차 중심 클라이언트라
설정도 별도 어댑터 계층 없이 argparse 와 환경변수만으로 단순하게 읽는다. AWS 자격증명은 여기서
다루지 않고 표준 AWS SDK 자격증명 체인에 위임한다.

각 플래그는 기본값으로 대응 환경변수를 먼저 반영하고, 명시된 플래그가 그 위에 우선한다(CLI 관례).
region 과 sts-endpoint 는 반드시 일치해야 하는데 기본값이 독립 소스라 충돌할 수 있어, 두 손잡이의
"명시 강도"를 비교해 더 강하게 명시된 쪽에서 약한 쪽을 파생한다.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlsplit

from shared.duration import DurationError, parse_duration

# AWS 리전 식별자의 형식. 표준(us-east-1), gov(us-gov-west-1), cn(cn-north-1) 형태를 모두 포용한다.
# 실재 여부는 형식만으로 판별할 수 없으므로, 이 검사는 리전답지 않은 문자열만 거른다.
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")

# 증명 형태 값.
_FORM_HEADER = "header"
_FORM_PRESIGNED = "presigned"

# presigned 만료(X-Amz-Expires)의 기본값. 서버 정책 기본값 policy.request_max_age(5m)와 맞춘다.
_DEFAULT_PRESIGN_EXPIRY = "5m"

# presigned 만료의 상한. 서버 수신 어댑터의 MAX_PRESIGN_EXPIRY_SECONDS(604800s, AWS presigned 최대
# 7일)와 같은 값이다. 두 값이 어긋나면 크로스모듈 e2e 테스트가 초 환산 동일성을 단언한다.
MAX_PRESIGN_EXPIRY = timedelta(days=7)


class ConfigError(ValueError):
    """설정 로드/검증 실패."""


@dataclass(frozen=True)
class Config:
    """클라이언트가 증명을 만들어 보내는 데 필요한 설정 묶음. 기본값은 서버 config.yaml 과
    정렬해, 로컬 데모가 추가 설정 없이 바로 통과하도록 맞춘다.
    """

    server_addr: str
    binding_value: str
    sts_endpoint: str
    region: str
    form: str
    presign_expiry: timedelta
    verify: bool
    timeout: timedelta
    static_creds: bool
    static_access_key_id: str
    static_secret_key: str
    static_session_token: str

    def is_presigned(self) -> bool:
        """증명 형태가 presigned 인지 돌려준다."""

        return self.form == _FORM_PRESIGNED


def _env_or(getenv: Callable[[str], str], key: str, fallback: str) -> str:
    """환경변수 key 가 비어 있지 않으면 그 값을, 아니면 fallback 을 돌려준다."""

    v = getenv(key)
    return v if v else fallback


def _env_bool(getenv: Callable[[str], str], key: str) -> bool:
    """불리언 환경변수를 해석한다(Go strconv.ParseBool 의 참 값에 대응). 미설정/해석 불가는 거짓."""

    return getenv(key).strip() in ("1", "t", "T", "TRUE", "true", "True")


def load(argv: Sequence[str], getenv: Callable[[str], str]) -> Config:
    """인자 목록과 환경 조회 함수로 설정을 만들어 검증한다. 실행용 진입점(main)은 sys.argv[1:] 와
    os.environ.get 을 넘기고, 테스트는 인자/환경 조회를 주입한다.
    """

    parser = argparse.ArgumentParser(prog="client", description="샘플 워크로드 클라이언트")
    parser.add_argument("--server-addr", default=None, help="요청을 보낼 대상 서버 주소")
    parser.add_argument(
        "--binding-value", default=None, help="서명 범위에 넣을 서버 바인딩 헤더 값"
    )
    parser.add_argument(
        "--sts-endpoint", default=None, help="SigV4 서명/위임 대상 STS 엔드포인트(https)"
    )
    parser.add_argument("--region", default=None, help="SigV4 서명 리전")
    parser.add_argument("--form", default=None, help="증명 형태(header/presigned)")
    parser.add_argument("--presign-expiry", default=None, help="presigned 만료(X-Amz-Expires)")
    parser.add_argument(
        "--verify", action="store_true", default=None, help="발급 토큰을 /verify 로 왕복 확인"
    )
    parser.add_argument("--timeout", default=None, help="실행 전체의 최대 소요 시간")
    parser.add_argument(
        "--static-creds", action="store_true", default=None, help="static 자격증명으로 서명"
    )
    parser.add_argument("--static-access-key-id", default=None, help="static 자격증명 액세스 키 ID")
    parser.add_argument("--static-secret-key", default=None, help="static 자격증명 시크릿 키")
    parser.add_argument("--static-session-token", default=None, help="static 자격증명 세션 토큰")

    ns = parser.parse_args(list(argv))

    def flag_or_env(flag_val: str | None, env_key: str, default: str) -> str:
        """플래그 값이 명시되면 그것을, 아니면 env-or-default 를 돌려준다."""

        return flag_val if flag_val is not None else _env_or(getenv, env_key, default)

    server_addr = flag_or_env(ns.server_addr, "SERVER_ADDR", "http://localhost:8080")
    binding_value = flag_or_env(
        ns.binding_value, "CLIENT_BINDING_VALUE", "https://server.example/audience"
    )

    region_flag_set = ns.region is not None
    endpoint_flag_set = ns.sts_endpoint is not None
    region = flag_or_env(ns.region, "AWS_REGION", "us-east-1")
    endpoint = flag_or_env(ns.sts_endpoint, "STS_ENDPOINT", "https://sts.amazonaws.com")

    form = flag_or_env(ns.form, "CLIENT_PROOF_FORM", _FORM_HEADER)
    presign_raw = flag_or_env(ns.presign_expiry, "CLIENT_PRESIGN_EXPIRY", _DEFAULT_PRESIGN_EXPIRY)
    verify = ns.verify if ns.verify is not None else _env_bool(getenv, "CLIENT_VERIFY")
    timeout_raw = flag_or_env(ns.timeout, "CLIENT_TIMEOUT", "30s")

    static_creds = (
        ns.static_creds if ns.static_creds is not None else _env_bool(getenv, "CLIENT_STATIC_CREDS")
    )
    static_access_key_id = flag_or_env(ns.static_access_key_id, "CLIENT_STATIC_ACCESS_KEY_ID", "")
    static_secret_key = flag_or_env(ns.static_secret_key, "CLIENT_STATIC_SECRET_KEY", "")
    static_session_token = flag_or_env(ns.static_session_token, "CLIENT_STATIC_SESSION_TOKEN", "")

    # 타임아웃/만료는 서버 어댑터의 duration 파싱과 같은 톤으로 해석한다. 형식 오류는 로드 시점에.
    try:
        timeout = parse_duration(timeout_raw)
    except DurationError as e:
        raise ConfigError(f"timeout 파싱 실패({timeout_raw!r}): {e}") from e
    try:
        presign_expiry = parse_duration(presign_raw)
    except DurationError as e:
        raise ConfigError(f"presign-expiry 파싱 실패({presign_raw!r}): {e}") from e

    # region 과 sts-endpoint 의 "명시 강도"를 비교해, 더 강하게 명시된 쪽에서 약한 쪽을 파생한다.
    # 강도: 0=기본, 1=환경변수, 2=플래그. 강도가 같으면 그대로 두고 validate 가 정합성을 검사한다.
    def strength(flag_set: bool, env_key: str) -> int:
        s = 0
        if getenv(env_key):
            s = 1
        if flag_set:
            s = 2
        return s

    region_strength = strength(region_flag_set, "AWS_REGION")
    endpoint_strength = strength(endpoint_flag_set, "STS_ENDPOINT")

    if region_strength > endpoint_strength:
        derived = _endpoint_for_region(region)
        if derived is not None:
            endpoint = derived
    elif endpoint_strength > region_strength:
        derived_region = _region_for_sts_host(urlsplit(endpoint).hostname or "")
        if derived_region is not None:
            region = derived_region

    cfg = Config(
        server_addr=server_addr,
        binding_value=binding_value,
        sts_endpoint=endpoint,
        region=region,
        form=form,
        presign_expiry=presign_expiry,
        verify=verify,
        timeout=timeout,
        static_creds=static_creds,
        static_access_key_id=static_access_key_id,
        static_secret_key=static_secret_key,
        static_session_token=static_session_token,
    )
    _validate(cfg)
    return cfg


def _validate(c: Config) -> None:
    """필수값과 형태 제약을 확인한다. 빈 값/형식 오류를 로드 시점에 명확히 드러낸다."""

    if c.server_addr == "":
        raise ConfigError("server-addr 가 비어 있음")
    if c.binding_value == "":
        raise ConfigError("binding-value 가 비어 있음(서버 policy.binding_value 와 일치해야 함)")

    # STS 엔드포인트는 비어 있지 않을 뿐 아니라 https 여야 한다(서버가 비-https 위임 대상을 거부).
    parts = urlsplit(c.sts_endpoint)
    if parts.scheme != "https" or parts.netloc == "":
        raise ConfigError(
            f"sts-endpoint 는 https URL 이어야 함(현재 {c.sts_endpoint!r}): "
            "서버가 비-https 위임 대상을 거부한다"
        )

    if c.region == "":
        raise ConfigError("region 이 비어 있음")
    if not _AWS_REGION_RE.match(c.region):
        raise ConfigError(
            f"region 형식이 올바르지 않음({c.region!r}): AWS 리전 형식이어야 함(예: us-east-1)"
        )

    # 표준 STS 호스트에서 리전을 파생할 수 있으면 서명 리전과 대조한다(절반-수정 방지).
    derived = _region_for_sts_host(parts.hostname or "")
    if derived is not None and derived != c.region:
        raise ConfigError(
            f"region({c.region!r}) 과 sts-endpoint 리전({derived!r})이 불일치: "
            "서명 리전과 엔드포인트가 맞아야 STS 가 서명을 검증한다"
        )

    if c.form == _FORM_HEADER:
        # 헤더 기반은 만료를 클라이언트가 지정하지 않으므로 presign_expiry 는 무의미(검증 안 함).
        pass
    elif c.form == _FORM_PRESIGNED:
        # presigned 는 X-Amz-Expires 로 만료를 직접 지정하므로 양의 초 단위여야 한다.
        not_whole = c.presign_expiry % timedelta(seconds=1) != timedelta(0)
        if c.presign_expiry <= timedelta(0) or not_whole:
            raise ConfigError(
                f"presign-expiry 는 양의 초 단위여야 함(현재 {c.presign_expiry}): "
                "X-Amz-Expires 는 초 단위 정수라 1초 미만/소수 초는 잘린다"
            )
        if c.presign_expiry > MAX_PRESIGN_EXPIRY:
            raise ConfigError(
                f"presign-expiry 는 상한({MAX_PRESIGN_EXPIRY}) 이내여야 함"
                f"(현재 {c.presign_expiry}): 서버가 상한 초과 X-Amz-Expires 를 거부한다"
            )
    else:
        raise ConfigError(f"form 값이 올바르지 않음({c.form!r}): header/presigned 만 지원")

    if c.timeout <= timedelta(0):
        raise ConfigError(
            f"timeout 은 양수여야 함(현재 {c.timeout}): 0 이하면 요청 경계가 없어진다"
        )

    if c.static_creds and (c.static_access_key_id == "" or c.static_secret_key == ""):
        raise ConfigError(
            "static-creds 사용 시 static-access-key-id 와 static-secret-key 가 필요함"
        )


def _region_for_sts_host(host: str) -> str | None:
    """표준 AWS STS 호스트에서 SigV4 서명 리전을 파생한다. 판정 가능한 표준 형태만 다루고, 그 외는
    None 을 돌려 정합성 검사를 건너뛰게 한다(과잉 거부 방지).
    """

    host = host.lower()
    if host == "sts.amazonaws.com":
        return "us-east-1"
    parts = host.split(".")
    sts_label = len(parts) > 0 and parts[0] in ("sts", "sts-fips")
    if len(parts) == 4 and sts_label and parts[2] == "amazonaws" and parts[3] == "com":
        return parts[1]  # 표준/gov: sts.<region>.amazonaws.com
    if (
        len(parts) == 5
        and sts_label
        and parts[2] == "amazonaws"
        and parts[3] == "com"
        and parts[4] == "cn"
    ):
        return parts[1]  # 중국: sts.<region>.amazonaws.com.cn
    if len(parts) == 4 and parts[0] == "sts" and parts[2] == "api" and parts[3] == "aws":
        return parts[1]  # dualstack: sts.<region>.api.aws
    return None


def _endpoint_for_region(region: str) -> str | None:
    """서명 리전에서 표준 STS 엔드포인트 URL 을 파생한다. 확실히 조립할 수 있는 표준/gov 파티션만
    다루고, 그 외(중국 등)는 None 을 돌려 호출부가 명시를 요구하게 한다.
    """

    if region == "us-east-1":
        return "https://sts.amazonaws.com"  # global(서버 기본 allowlist 와 정렬)
    if region.startswith("cn-"):
        return None  # 중국 파티션은 .amazonaws.com.cn 이라 파생하지 않는다(명시 필요)
    return f"https://sts.{region}.amazonaws.com"
