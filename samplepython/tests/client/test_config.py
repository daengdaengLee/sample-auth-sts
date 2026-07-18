"""클라이언트 설정 로드/검증/리전 파생 테스트."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import timedelta

import pytest

from client.config import Config, ConfigError, load


def _getenv(env: Mapping[str, str]) -> Callable[[str], str]:
    return lambda k: env.get(k, "")


def _load(args: list[str], env: Mapping[str, str] | None = None) -> Config:
    return load(args, _getenv(env or {}))


def test_defaults() -> None:
    cfg = _load([])
    assert cfg.server_addr == "http://localhost:8080"
    assert cfg.region == "us-east-1"
    assert cfg.sts_endpoint == "https://sts.amazonaws.com"
    assert cfg.form == "header"
    assert not cfg.verify
    assert cfg.timeout == timedelta(seconds=30)


def test_region_flag_derives_endpoint() -> None:
    cfg = _load(["--region", "us-west-2"])
    assert cfg.sts_endpoint == "https://sts.us-west-2.amazonaws.com"


def test_endpoint_flag_derives_region() -> None:
    cfg = _load(["--sts-endpoint", "https://sts.eu-west-1.amazonaws.com"])
    assert cfg.region == "eu-west-1"


def test_endpoint_flag_beats_env_region() -> None:
    cfg = _load(
        ["--sts-endpoint", "https://sts.eu-west-1.amazonaws.com"],
        {"AWS_REGION": "us-west-2"},
    )
    assert cfg.region == "eu-west-1"


def test_env_region_derives_endpoint() -> None:
    cfg = _load([], {"AWS_REGION": "ap-northeast-2"})
    assert cfg.sts_endpoint == "https://sts.ap-northeast-2.amazonaws.com"


def test_mismatch_both_explicit_rejected() -> None:
    with pytest.raises(ConfigError, match="불일치"):
        _load(["--region", "us-east-1", "--sts-endpoint", "https://sts.us-west-2.amazonaws.com"])


def test_bad_region_format_rejected() -> None:
    with pytest.raises(ConfigError, match="region 형식"):
        _load(["--region", "not_a_region", "--sts-endpoint", "https://custom.example"])


def test_http_endpoint_rejected() -> None:
    with pytest.raises(ConfigError, match="https"):
        _load(["--sts-endpoint", "http://sts.amazonaws.com", "--region", "us-east-1"])


def test_presigned_ok() -> None:
    cfg = _load(["--form", "presigned", "--presign-expiry", "1m"])
    assert cfg.is_presigned()
    assert cfg.presign_expiry == timedelta(minutes=1)


def test_presigned_sub_second_rejected() -> None:
    with pytest.raises(ConfigError, match="초 단위"):
        _load(["--form", "presigned", "--presign-expiry", "500ms"])


def test_presigned_over_max_rejected() -> None:
    # 7일(168h) 상한 초과. Go duration 은 일(d) 단위가 없어 시간으로 표기한다.
    with pytest.raises(ConfigError, match="상한"):
        _load(["--form", "presigned", "--presign-expiry", "200h"])


def test_invalid_form_rejected() -> None:
    with pytest.raises(ConfigError, match="form"):
        _load(["--form", "bogus"])


def test_static_creds_require_keys() -> None:
    with pytest.raises(ConfigError, match="static"):
        _load(["--static-creds"])


def test_static_creds_ok() -> None:
    cfg = _load(
        ["--static-creds", "--static-access-key-id", "AKID", "--static-secret-key", "secret"]
    )
    assert cfg.static_creds
    assert cfg.static_access_key_id == "AKID"


def test_env_verify_bool() -> None:
    assert _load([], {"CLIENT_VERIFY": "true"}).verify is True
    assert _load([], {"CLIENT_VERIFY": "0"}).verify is False
