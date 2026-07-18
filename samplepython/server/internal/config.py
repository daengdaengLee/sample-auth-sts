"""서버의 공유 설정 로더.

config.yaml(현재 작업 디렉토리)을 읽어 섹션별 설정 객체(jwt/policy/sts)를 만들고, 환경변수가
파일값 위에 우선하도록 override 를 건다. Go 의 viper(AutomaticEnv + 점->밑줄 replacer)에 대응한다.

pydantic-settings 를 쓰되 env_nested_delimiter 는 쓰지 않는다: 키 이름 자체에 밑줄이 든 경우
(예: signing_secret)와 충돌해 JWT_SIGNING_SECRET 이 jwt->signing->secret 으로 잘못 분해되기
때문이다. 대신 섹션마다 env_prefix(JWT_/POLICY_/STS_)를 주고, 같은 config.yaml 의 해당 섹션을
init 값으로 넣되 소스 우선순위를 env 가 init 보다 높게 두어(settings_customise_sources) "env 가
파일값을 덮어쓴다"는 viper 의미를 그대로 재현한다. 값은 모두 문자열로 받고, 타입/필수/형식
검증은 각 어댑터의 load()가 부팅 시점에 수행한다(Go 어댑터 Load 관례와 동일).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

_CONFIG_FILENAME = "config.yaml"


def _env_first(
    env_settings: PydanticBaseSettingsSource,
    init_settings: PydanticBaseSettingsSource,
) -> tuple[PydanticBaseSettingsSource, ...]:
    """소스 우선순위를 env -> init(yaml) 순으로 둔다. 앞이 높은 우선순위이므로 환경변수가
    파일값(init 으로 주입)을 덮어쓴다.
    """

    return (env_settings, init_settings)


class JwtSettings(BaseSettings):
    """jwt 섹션의 원시 문자열 값. env override: JWT_SIGNING_SECRET 등."""

    model_config = SettingsConfigDict(env_prefix="JWT_", extra="ignore")

    signing_secret: str = ""
    ttl: str = ""
    issuer: str = ""
    audience: str = ""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return _env_first(env_settings, init_settings)


class PolicySettings(BaseSettings):
    """policy 섹션의 원시 문자열 값. env override: POLICY_BINDING_VALUE 등."""

    model_config = SettingsConfigDict(env_prefix="POLICY_", extra="ignore")

    binding_value: str = ""
    request_max_age: str = ""
    allowed_arns: str = ""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return _env_first(env_settings, init_settings)


class StsSettings(BaseSettings):
    """sts 섹션의 원시 문자열 값. env override: STS_ENDPOINT_ALLOWLIST, STS_CA_FILE."""

    model_config = SettingsConfigDict(env_prefix="STS_", extra="ignore")

    endpoint_allowlist: str = ""
    ca_file: str = ""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return _env_first(env_settings, init_settings)


@dataclass(frozen=True)
class AppConfig:
    """섹션별 설정을 묶은 공유 설정. 조립 루트가 각 어댑터 load()로 넘긴다."""

    jwt: JwtSettings
    policy: PolicySettings
    sts: StsSettings


def _read_section(data: dict[str, Any], section: str) -> dict[str, str]:
    """config.yaml 의 한 섹션을 문자열 dict 로 만든다. viper GetString 처럼 스칼라를 문자열로
    강제한다(None 은 빈 문자열).
    """

    raw = data.get(section) or {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): ("" if v is None else str(v)) for k, v in raw.items()}


def load(dir_path: str = ".") -> AppConfig:
    """dir_path 에서 config.yaml 을 찾아 읽어 섹션별 설정을 만든다. 서버는 실행 위치(".")를,
    테스트는 임시 디렉토리를 넘긴다. 파일이 없거나 파싱에 실패하면 예외를 던져 오설정을 부팅
    시점에 드러낸다.
    """

    path = Path(dir_path) / _CONFIG_FILENAME
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"설정 파일({path}) 로드 실패: {e}") from e

    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise RuntimeError(f"설정 파일({path}) 최상위가 매핑이 아님")

    return AppConfig(
        jwt=JwtSettings(**_read_section(data, "jwt")),
        policy=PolicySettings(**_read_section(data, "policy")),
        sts=StsSettings(**_read_section(data, "sts")),
    )
