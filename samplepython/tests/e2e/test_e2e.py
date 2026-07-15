"""크로스모듈 e2e: 실제 서버 라우터 + 실제 아웃바운드 어댑터(STS 위임 포함)를 조립하고, TLS 목
STS 로 위임을 흉내내며, 실제 클라이언트 proof 엔벨로프가 서버 와이어 계약과 맞물리는지 검증한다.
서버 검증 로직을 복제하지 않는다(Go client/internal/e2e 에 대응).
"""

from __future__ import annotations

import logging
import os
import ssl
import tempfile
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from botocore.credentials import Credentials
from fastapi.testclient import TestClient

from client import proof
from client.config import MAX_PRESIGN_EXPIRY
from client.transport import Client
from server.adapter.inbound.auth import MAX_PRESIGN_EXPIRY_SECONDS
from server.adapter.inbound.router import create_app
from server.adapter.outbound import clock, issuer, sts
from server.adapter.outbound import config as policyconfig
from server.cmd.mocksts import _build_response_xml
from server.domain.service import Service
from server.domain.verify_service import VerifyService
from server.internal.config import JwtSettings, PolicySettings

_TEST_ARN = "arn:aws:iam::123456789012:role/workload"
_TEST_ACCOUNT = "123456789012"
_TEST_USER_ID = "AIDAEXAMPLE"
_TEST_BINDING = "https://server.example/audience"
_TEST_SECRET = "e2e-test-hs256-secret-change-me-please-32b"
_TEST_ISSUER = "https://server.example"
_TEST_AUDIENCE = "https://server.example/clients"


class _MockSTS:
    """서명을 검증하지 않고 고정 GetCallerIdentity XML 을 돌려주는 TLS 목 STS."""

    def __init__(self) -> None:
        self._xml = _build_response_xml(_TEST_ARN, _TEST_ACCOUNT, _TEST_USER_ID)
        from server.internal.democert import generate

        cert_pem, key_pem = generate(["localhost", "127.0.0.1", "::1"])
        self._cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        self._cert_file.write(cert_pem)
        self._cert_file.close()
        self._key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        self._key_file.write(key_pem)
        self._key_file.close()

        xml = self._xml
        self.received_method: str | None = None
        self.received_path: str | None = None
        self.received_binding: str | None = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self) -> None:
                outer.received_method = self.command
                outer.received_path = self.path
                outer.received_binding = self.headers.get("X-Server-Binding")
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length:
                    self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "text/xml")
                self.send_header("Content-Length", str(len(xml)))
                self.end_headers()
                self.wfile.write(xml)

            def do_GET(self) -> None:  # noqa: N802
                self._reply()

            def do_POST(self) -> None:  # noqa: N802
                self._reply()

            def log_message(self, *args: object) -> None:
                pass

        self._httpd = HTTPServer(("localhost", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._cert_file.name, self._key_file.name)
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        self.port = self._httpd.server_address[1]
        self.url = f"https://localhost:{self.port}"
        self.ca_file = self._cert_file.name
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        os.unlink(self._cert_file.name)
        os.unlink(self._key_file.name)


@pytest.fixture
def mock_sts() -> Iterator[_MockSTS]:
    server = _MockSTS()
    try:
        yield server
    finally:
        server.close()


def _assemble_app(sts_url: str, ca_file: str) -> TestClient:
    """실제 라우터 + 실제 아웃바운드 어댑터(STS 위임 포함)를 조립한다."""

    params = issuer.load(
        JwtSettings(
            signing_secret=_TEST_SECRET,
            ttl="15m",
            issuer=_TEST_ISSUER,
            audience=_TEST_AUDIENCE,
        )
    )
    policy = policyconfig.load(
        PolicySettings(
            binding_value=_TEST_BINDING,
            request_max_age="5m",
            allowed_arns=_TEST_ARN,
        )
    )
    http_client = sts.build_client(timeout=5.0, ca_file=ca_file)
    verifier = sts.new(http_client, [sts_url])
    clk = clock.new()
    svc = Service(policy, clk, verifier, issuer.new(params))
    vsvc = VerifyService(clk, issuer.new_inspector(params), issuer.new_verify_policy(params))
    app = create_app(logging.getLogger("e2e"), svc, vsvc)
    return TestClient(app)


def test_presign_expiry_bounds_agree() -> None:
    """클라이언트 MAX_PRESIGN_EXPIRY(초)와 서버 MAX_PRESIGN_EXPIRY_SECONDS 가 일치해야 한다
    (한쪽만 바뀌면 로컬 수락 -> 원격 거부가 재발한다).
    """

    assert int(MAX_PRESIGN_EXPIRY.total_seconds()) == MAX_PRESIGN_EXPIRY_SECONDS


def test_client_end_to_end_header(mock_sts: _MockSTS) -> None:
    """헤더 기반: 실제 클라이언트 proof -> 실제 라우터/STS 어댑터 -> 목 STS -> JWT -> /verify."""

    tc = _assemble_app(mock_sts.url, mock_sts.ca_file)
    creds = Credentials("AKIDEXAMPLE", "secretexamplekey")
    envelope = proof.build_proof(creds, mock_sts.url + "/", "us-east-1", _TEST_BINDING)

    client = Client("", tc)
    result = client.post_auth(envelope)
    assert len(result.token.split(".")) == 3

    # 목 STS 가 헤더 기반 POST 와 바인딩 헤더를 받았는지 확인한다.
    assert mock_sts.received_method == "POST"
    assert mock_sts.received_binding == _TEST_BINDING

    claims = client.post_verify(result.token)
    assert claims.subject == _TEST_ARN
    assert claims.issuer == _TEST_ISSUER
    assert claims.audience == _TEST_AUDIENCE
    assert claims.account == _TEST_ACCOUNT


def test_client_end_to_end_presigned(mock_sts: _MockSTS) -> None:
    """presigned: 실제 클라이언트 proof(GET/쿼리 서명) -> 실제 라우터/STS 어댑터 -> 목 STS."""

    tc = _assemble_app(mock_sts.url, mock_sts.ca_file)
    creds = Credentials("AKIDEXAMPLE", "secretexamplekey")
    envelope = proof.build_presigned_proof(
        creds, mock_sts.url + "/", "us-east-1", _TEST_BINDING, 120
    )

    client = Client("", tc)
    result = client.post_auth(envelope)
    assert len(result.token.split(".")) == 3

    assert mock_sts.received_method == "GET"
    assert mock_sts.received_binding == _TEST_BINDING

    claims = client.post_verify(result.token)
    assert claims.subject == _TEST_ARN
    assert claims.account == _TEST_ACCOUNT
