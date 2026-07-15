"""클라이언트 proof(SigV4 서명 + 엔벨로프) 테스트. botocore 시각을 freeze 해 결정적으로 만든다."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import botocore.auth
import pytest
from botocore.credentials import Credentials

from client import proof

_BINDING = "https://server.example/audience"
_ENDPOINT = "https://sts.amazonaws.com/"


@pytest.fixture
def frozen_time() -> Iterator[None]:
    fixed = datetime(2026, 7, 9, 12, 0, 0, tzinfo=UTC)
    orig = botocore.auth.get_current_datetime
    botocore.auth.get_current_datetime = lambda: fixed
    try:
        yield
    finally:
        botocore.auth.get_current_datetime = orig


def _creds(token: str | None = None) -> Credentials:
    return Credentials("AKIDEXAMPLE", "secretexamplekey", token)


def _signed_header_set(authorization: str) -> set[str]:
    marker = "SignedHeaders="
    rest = authorization[authorization.index(marker) + len(marker) :]
    rest = rest.split(",")[0]
    return {h.strip().lower() for h in rest.split(";")}


def test_header_form_signs_binding_and_date(frozen_time: None) -> None:
    env = proof.build_proof(_creds(), _ENDPOINT, "us-east-1", _BINDING)
    assert env.method == "POST"
    assert env.url == _ENDPOINT
    # 본문은 정확한 폼 바디의 base64.
    assert base64.standard_b64decode(env.body) == b"Action=GetCallerIdentity&Version=2011-06-15"
    # Authorization 의 SignedHeaders 에 host/x-amz-date/x-server-binding 이 들어야 한다.
    authz = env.headers["Authorization"][0]
    signed = _signed_header_set(authz)
    assert {"host", "x-amz-date", "x-server-binding"} <= signed
    # X-Amz-Date 는 freeze 한 시각.
    assert env.headers["X-Amz-Date"] == ["20260709T120000Z"]
    # 바인딩과 Host 가 엔벨로프에 실려 있어야 한다.
    assert env.headers["X-Server-Binding"] == [_BINDING]
    assert env.headers["Host"] == ["sts.amazonaws.com"]


def test_header_form_includes_session_token(frozen_time: None) -> None:
    env = proof.build_proof(_creds("SESSIONTOKEN"), _ENDPOINT, "us-east-1", _BINDING)
    # 임시 자격증명이면 X-Amz-Security-Token 이 헤더로 실린다.
    assert "X-Amz-Security-Token" in {k for k in env.headers}


def test_presigned_form_query_signature(frozen_time: None) -> None:
    env = proof.build_presigned_proof(_creds(), _ENDPOINT, "us-east-1", _BINDING, 120)
    assert env.method == "GET"
    assert env.body == ""
    q = parse_qs(urlsplit(env.url).query)
    # SigV4 쿼리 파라미터가 각각 정확히 1개.
    for key in ("X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Signature", "X-Amz-Date"):
        assert len(q[key]) == 1
    assert q["X-Amz-Expires"] == ["120"]
    assert q["Action"] == ["GetCallerIdentity"]
    # SignedHeaders 에 x-server-binding 포함.
    assert "x-server-binding" in q["X-Amz-SignedHeaders"][0].split(";")
    # 바인딩은 실제 헤더로 실린다(쿼리가 아니라).
    assert env.headers["X-Server-Binding"] == [_BINDING]


def test_presigned_form_session_token_in_query(frozen_time: None) -> None:
    env = proof.build_presigned_proof(_creds("SESSIONTOKEN"), _ENDPOINT, "us-east-1", _BINDING, 120)
    q = parse_qs(urlsplit(env.url).query)
    assert q["X-Amz-Security-Token"] == ["SESSIONTOKEN"]
