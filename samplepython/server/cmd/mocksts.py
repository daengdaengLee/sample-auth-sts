"""실 AWS 없이 로컬 데모를 돌리기 위한 목(mock) AWS STS. TLS 로 서빙하며, 받은 요청의 SigV4
서명을 검증하지 않고 GetCallerIdentity 성공 XML(고정 ARN/Account/UserId)을 돌려준다. 부팅 때
self-signed 인증서를 생성해 그 인증서(PEM)를 신뢰 앵커로 --ca-out 경로에 내보내며, 서버는 이를
sts.ca_file(STS_CA_FILE)로 신뢰해 server -> 목 STS 위임의 TLS 를 잇는다.

이 커맨드는 오로지 데모 전용이다. 서명을 전혀 검증하지 않으므로 실 배포에서는 절대 쓰지 말 것.

개인키 처리: 파이썬 stdlib ssl 은 in-memory 키를 받지 않고 파일 경로만 받으므로, 개인키는 잘
알려진 경로가 아니라 권한 0600 의 임시 파일에 써서 TLS 기동에만 쓰고 종료 시 삭제한다. --ca-out
파일은 인증서만 담긴 채로 유지한다(신뢰 앵커는 공개 인증서).
"""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from xml.etree import ElementTree

import uvicorn

from server.internal.democert import generate

# 목 STS 가 리슨할 기본 주소. self-signed 인증서 SAN 에 든 localhost 로 맞춰, 서버/클라이언트가
# https://localhost:8443 을 그대로 쓰게 한다.
_DEFAULT_HOST = "localhost"
_DEFAULT_PORT = 8443

# 신뢰 앵커(인증서 PEM)를 쓸 기본 경로. 서버 cwd 에서 목 STS 를 실행하면 이 파일이 서버 cwd 에
# 놓여, STS_CA_FILE=./mocksts-ca.pem 으로 바로 가리킬 수 있다.
_DEFAULT_CA_OUT = "mocksts-ca.pem"

# GetCallerIdentity 성공 응답에 실을 기본 신원. 기본 ARN 은 서버 config.yaml 의
# policy.allowed_arns 기본값과 일치시켜, 추가 설정 없이 데모가 통과하게 한다.
_DEFAULT_ARN = "arn:aws:iam::123456789012:role/workload"
_DEFAULT_ACCOUNT = "123456789012"
_DEFAULT_USER_ID = "AIDAEXAMPLE"

# GetCallerIdentity 응답의 XML 네임스페이스(실제 STS 와 동일). 서버 STS 어댑터는 로컬 이름 기준으로
# 파싱해 네임스페이스를 무시하지만, 실제 응답 형태와 맞춰 둔다.
_STS_NAMESPACE = "https://sts.amazonaws.com/doc/2011-06-15/"

_Scope = dict[str, object]
_Receive = Callable[[], Awaitable[dict[str, object]]]
_Send = Callable[[dict[str, object]], Awaitable[None]]


def _build_response_xml(arn: str, account: str, user_id: str) -> bytes:
    """GetCallerIdentity 성공 응답(XML)을 만든다. ElementTree 로 마샬해 값에 XML 메타문자가 들어도
    안전하게 이스케이프한다. 서버 STS 어댑터가 로컬 이름 기준으로 뽑으므로 요소 이름만 맞으면 된다.
    """

    root = ElementTree.Element("GetCallerIdentityResponse", {"xmlns": _STS_NAMESPACE})
    result = ElementTree.SubElement(root, "GetCallerIdentityResult")
    ElementTree.SubElement(result, "Arn").text = arn
    ElementTree.SubElement(result, "UserId").text = user_id
    ElementTree.SubElement(result, "Account").text = account
    return bytes(ElementTree.tostring(root, encoding="utf-8"))


def _make_app(logger: logging.Logger, xml_body: bytes) -> Callable[..., Awaitable[None]]:
    """메서드/경로와 무관하게(헤더 기반 POST, presigned GET 모두) 서명을 검증하지 않고 고정 신원의
    GetCallerIdentity 성공 XML 을 돌려주는 ASGI 앱을 만든다.
    """

    async def app(scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] != "http":
            return
        # 본문을 끝까지 읽어 커넥션 재사용을 돕는다(내용은 검증하지 않는다).
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        logger.info("위임 수신", extra={"method": scope.get("method"), "path": scope.get("path")})
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/xml")],
            }
        )
        await send({"type": "http.response.body", "body": xml_body})

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="데모 전용 목 AWS STS(서명 미검증)")
    parser.add_argument("--host", default=_DEFAULT_HOST, help="목 STS 가 리슨할 호스트(TLS)")
    parser.add_argument(
        "--port", type=int, default=_DEFAULT_PORT, help="목 STS 가 리슨할 포트(TLS)"
    )
    parser.add_argument(
        "--ca-out",
        default=_DEFAULT_CA_OUT,
        help="신뢰 앵커(인증서 PEM)를 쓸 경로(서버 STS_CA_FILE 이 가리킬 파일)",
    )
    parser.add_argument(
        "--arn",
        default=_DEFAULT_ARN,
        help="GetCallerIdentity 로 돌려줄 ARN(서버 policy.allowed_arns 와 일치해야 함)",
    )
    parser.add_argument(
        "--account", default=_DEFAULT_ACCOUNT, help="GetCallerIdentity 로 돌려줄 Account"
    )
    parser.add_argument(
        "--user-id", default=_DEFAULT_USER_ID, help="GetCallerIdentity 로 돌려줄 UserId"
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    logger = logging.getLogger("mocksts")

    # SAN 에 localhost 와 루프백 IP 를 모두 넣어, 서버/클라이언트가 어느 이름으로 접속하든 TLS
    # 검증이 통과하게 한다(InsecureSkipVerify 를 쓰지 않으므로 SAN 이 맞아야 한다).
    cert_pem, key_pem = generate(["localhost", "127.0.0.1", "::1"])

    # 서버가 신뢰할 수 있도록 인증서(PEM)를 먼저 디스크에 쓴다. 0o644: 데모 신뢰 앵커는 비밀이
    # 아니라 공개 인증서다.
    ca_out = Path(args.ca_out)
    ca_out.write_bytes(cert_pem)
    os.chmod(ca_out, 0o644)

    # 개인키는 잘 알려진 경로가 아니라 권한 0600 의 임시 파일에 써서 TLS 기동에만 쓴다.
    key_fd, key_path = tempfile.mkstemp(prefix="mocksts-key-", suffix=".pem")
    try:
        with os.fdopen(key_fd, "wb") as f:
            f.write(key_pem)
        os.chmod(key_path, 0o600)

        xml_body = _build_response_xml(args.arn, args.account, args.user_id)
        app = _make_app(logger, xml_body)

        logger.info("목 STS 시작(데모 전용, 서명 미검증): https://%s:%d", args.host, args.port)
        logger.info("신뢰 앵커(CA) 파일: %s -- 서버에 STS_CA_FILE 로 지정하세요", args.ca_out)

        # uvicorn 이 SIGINT/SIGTERM 에서 graceful 셧다운을 처리한다. certfile 은 self-signed 라
        # 인증서 자체가 체인이므로 ca-out 파일을 그대로 쓰고, keyfile 은 임시 파일을 쓴다.
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            ssl_certfile=str(ca_out),
            ssl_keyfile=key_path,
            log_level="warning",
        )
    finally:
        # 임시 개인키 파일을 지운다.
        try:
            os.unlink(key_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
