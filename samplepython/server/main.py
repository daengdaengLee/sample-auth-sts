"""샘플 신뢰 당사자(relying party) 서버. 조립 루트(build_services)에서 공유 설정과 다섯 개의
아웃바운드 어댑터(정책/시계/STS/발급/토큰 검사), 두 도메인 서비스를 조립해 두 인바운드 포트
(/auth, /verify)를 인바운드 라우터에 주입하고, uvicorn 으로 서빙한다.
"""

from __future__ import annotations

import logging
import os
import sys

import uvicorn
from fastapi import FastAPI

from server.adapter.inbound.router import create_app
from server.adapter.outbound import clock, issuer, sts
from server.adapter.outbound import config as policyconfig
from server.domain.ports import Authenticator, TokenVerifier
from server.domain.service import Service
from server.domain.verify_service import VerifyService
from server.internal import config as sharedconfig
from server.internal import logging as applogging

# LISTEN_ADDR 이 설정되지 않았을 때 사용하는 기본 리슨 주소(host:port).
_DEFAULT_HOST = "0.0.0.0"
_DEFAULT_PORT = 8080

# STS 위임 요청 한 건의 최대 소요 시간(초). 응답이 없을 때 인증 요청이 무한정 매달리지 않게 한다.
_STS_REQUEST_TIMEOUT = 10.0


def build_services(
    logger: logging.Logger,
) -> tuple[Authenticator, TokenVerifier]:
    """헥사고날 조립 루트. 공유 설정을 한 번 로드해 아웃바운드 어댑터(정책/시계/STS/발급/토큰
    검사)를 만들고, 두 도메인 서비스에 주입해 인바운드 포트 두 개를 돌려준다. 각 어댑터의 로드/
    검증 실패는 그대로 전파해 부팅 시점에 오설정을 드러낸다.
    """

    cfg = sharedconfig.load()

    policy = policyconfig.load(cfg.policy)
    issuer_params = issuer.load(cfg.jwt)

    clk = clock.new()

    # 데모 전용 STS CA 신뢰: sts.ca_file(STS_CA_FILE)이 설정돼 있으면 그 CA 만 배타적으로 신뢰하는
    # httpx 클라이언트를 만든다(실 AWS 없이 목 STS 의 self-signed 인증서를 신뢰). 미설정이면 시스템
    # 신뢰 저장소를 쓴다(실 STS 흐름). 검증 끄기(InsecureSkipVerify)는 절대 쓰지 않는다.
    ca_file = sts.load_ca_file(cfg.sts)
    http_client = sts.build_client(timeout=_STS_REQUEST_TIMEOUT, ca_file=ca_file)
    if ca_file != "":
        logger.info("데모 전용 STS CA 신뢰 로드", extra={"sts_ca_file": ca_file})

    # new_verifier 는 허용 엔드포인트를 읽어 Verifier 를 만들고, 유효 엔드포인트가 하나도 없으면
    # 예외로 부팅을 실패시킨다. "떠 있지만 모든 /auth 가 실패하는" 상태를 어댑터 경계에서 막는다.
    verifier = sts.new_verifier(http_client, cfg.sts)

    iss = issuer.new(issuer_params)

    # /verify 배선: 발급과 같은 시크릿으로 서명을 재검증하는 검사기와, 발급 설정의 iss/aud 기대값을
    # 노출하는 검증 정책으로 만료/발급자/대상을 판단하는 검증 서비스를 조립한다.
    inspector = issuer.new_inspector(issuer_params)
    verify_policy = issuer.new_verify_policy(issuer_params)
    token_verifier = VerifyService(clk, inspector, verify_policy)

    logger.info(
        "composition root assembled",
        extra={
            "sts_endpoint_count": verifier.allowed_endpoint_count(),
            "sts_timeout": _STS_REQUEST_TIMEOUT,
        },
    )

    return Service(policy, clk, verifier, iss), token_verifier


def build_app(logger: logging.Logger) -> FastAPI:
    """조립 루트를 태워 서빙 가능한 FastAPI 앱을 만든다."""

    auth, verify = build_services(logger)
    return create_app(logger, auth, verify)


def _parse_listen_addr(raw: str) -> tuple[str, int]:
    """LISTEN_ADDR("host:port" 또는 ":port")을 (host, port) 로 파싱한다. host 가 비면 기본
    host 로 채운다.
    """

    host, sep, port_str = raw.rpartition(":")
    if sep == "":
        # 콜론이 없으면 host 만 준 것으로 보고 기본 포트를 쓴다.
        return raw or _DEFAULT_HOST, _DEFAULT_PORT
    host = host or _DEFAULT_HOST
    try:
        port = int(port_str)
    except ValueError:
        port = _DEFAULT_PORT
    return host, port


def main() -> None:
    logger = applogging.new(level=logging.INFO)

    host, port = _DEFAULT_HOST, _DEFAULT_PORT
    if (addr := os.environ.get("LISTEN_ADDR", "")) != "":
        host, port = _parse_listen_addr(addr)

    # 조립/검증 실패(설정 로드, 정책/발급/STS 검증, CA 로드 등)는 부팅 오설정이므로, raw
    # 스택트레이스 대신 한 줄 에러 로그로 드러내고 종료한다(Go main 의 run 에러 경계 대응).
    try:
        app = build_app(logger)
    except Exception as e:  # noqa: BLE001 - 모든 부팅 실패를 깔끔한 로그로 드러낸다
        logger.error("server exited with error", extra={"error": str(e)})
        sys.exit(1)

    logger.info("server starting", extra={"host": host, "port": port})
    # uvicorn 이 SIGINT/SIGTERM 에서 graceful 셧다운을 처리한다. 접근 로그는 자체 미들웨어가
    # 남기므로 uvicorn 기본 접근 로그는 끈다.
    uvicorn.run(app, host=host, port=port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
