"""정책 설정 어댑터와 공유 설정 로더(env override) 테스트."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from server.adapter.outbound import config as policyconfig
from server.internal import config as sharedconfig
from server.internal.config import PolicySettings

_CONFIG_YAML = """
jwt:
  signing_secret: "sample-only-hs256-secret-change-me-in-real-deployments"
  ttl: "15m"
  issuer: "https://server.example"
  audience: "https://server.example/clients"
policy:
  binding_value: "https://server.example/audience"
  request_max_age: "5m"
  allowed_arns: "arn:aws:iam::123456789012:role/workload"
sts:
  endpoint_allowlist: "https://sts.amazonaws.com"
"""


def _write_config(tmp_path: Path) -> str:
    (tmp_path / "config.yaml").write_text(_CONFIG_YAML, encoding="utf-8")
    return str(tmp_path)


def test_policy_load_success() -> None:
    cfg = policyconfig.load(
        PolicySettings(
            binding_value="https://server.example/audience",
            request_max_age="5m",
            allowed_arns="a, b ,c",
        )
    )
    assert cfg.expected_binding() == "https://server.example/audience"
    assert cfg.max_age() == timedelta(minutes=5)
    assert cfg.is_allowed_arn("a")
    assert cfg.is_allowed_arn("b")
    assert not cfg.is_allowed_arn("z")


def test_policy_default_max_age() -> None:
    cfg = policyconfig.load(PolicySettings(binding_value="x", request_max_age="", allowed_arns=""))
    assert cfg.max_age() == timedelta(minutes=5)


def test_policy_empty_binding_rejected() -> None:
    with pytest.raises(ValueError, match="policy.binding_value"):
        policyconfig.load(PolicySettings(binding_value="", request_max_age="5m", allowed_arns=""))


def test_policy_bad_duration_rejected() -> None:
    with pytest.raises(ValueError, match="request_max_age"):
        policyconfig.load(
            PolicySettings(binding_value="x", request_max_age="notaduration", allowed_arns="")
        )


def test_policy_empty_allowlist_denies_all() -> None:
    cfg = policyconfig.load(
        PolicySettings(binding_value="x", request_max_age="5m", allowed_arns="")
    )
    assert not cfg.is_allowed_arn("anything")


def test_shared_config_loads_file(tmp_path: Path) -> None:
    cfg = sharedconfig.load(_write_config(tmp_path))
    assert cfg.jwt.issuer == "https://server.example"
    assert cfg.policy.binding_value == "https://server.example/audience"
    assert cfg.sts.endpoint_allowlist == "https://sts.amazonaws.com"


def test_shared_config_env_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SIGNING_SECRET", "env-secret-override")
    monkeypatch.setenv("POLICY_BINDING_VALUE", "https://env.example/aud")
    monkeypatch.setenv("STS_ENDPOINT_ALLOWLIST", "https://localhost:8443")
    cfg = sharedconfig.load(_write_config(tmp_path))
    assert cfg.jwt.signing_secret == "env-secret-override"
    assert cfg.policy.binding_value == "https://env.example/aud"
    assert cfg.sts.endpoint_allowlist == "https://localhost:8443"
    # 미설정 키는 파일값 유지.
    assert cfg.jwt.issuer == "https://server.example"


def test_shared_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="로드 실패"):
        sharedconfig.load(str(tmp_path / "nonexistent"))
