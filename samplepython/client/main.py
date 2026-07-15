"""샘플 워크로드 클라이언트. 보유한 AWS 자격증명으로 GetCallerIdentity 요청에 서명해 서버 /auth
로 보내고, 발급 토큰을 받은 뒤 --verify 를 주면 /verify 로 왕복 확인한다.

절차: 설정 로드 -> 자격증명 획득 -> 증명 형태/서명 -> 전송 -> (선택) 검증.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

import httpx
from botocore.credentials import Credentials
from botocore.session import Session

from client import proof
from client.config import Config, ConfigError, load
from client.envelope import Envelope
from client.transport import APIError, Client


def _load_credentials(cfg: Config) -> Credentials:
    """자격증명을 얻는다. static-creds 면 주어진 값으로, 아니면 표준 AWS SDK 자격증명 체인(환경
    변수, EC2 인스턴스 프로파일, IRSA, Pod Identity 등)에서 얻는다. GetCallerIdentity 는 별도
    권한이 필요 없다.
    """

    if cfg.static_creds:
        return Credentials(
            access_key=cfg.static_access_key_id,
            secret_key=cfg.static_secret_key,
            token=cfg.static_session_token or None,
        )

    session = Session()
    session.set_config_variable("region", cfg.region)
    creds = session.get_credentials()
    if creds is None:
        raise RuntimeError("AWS 자격증명을 찾을 수 없음(표준 SDK 자격증명 체인)")
    return creds


def _build_envelope(cfg: Config, credentials: Credentials) -> Envelope:
    """설정한 증명 형태로 서명된 엔벨로프를 만든다."""

    if cfg.is_presigned():
        return proof.build_presigned_proof(
            credentials,
            cfg.sts_endpoint,
            cfg.region,
            cfg.binding_value,
            int(cfg.presign_expiry.total_seconds()),
        )
    return proof.build_proof(credentials, cfg.sts_endpoint, cfg.region, cfg.binding_value)


def run(argv: Sequence[str]) -> int:
    """클라이언트 실행 본체. 성공 0, 실패 1 을 돌려준다."""

    try:
        cfg = load(argv, lambda k: os.environ.get(k, ""))
    except ConfigError as e:
        print(f"설정 오류: {e}", file=sys.stderr)
        return 1

    try:
        credentials = _load_credentials(cfg)
    except Exception as e:  # noqa: BLE001 - 자격증명 획득 실패를 사용자에게 그대로 알린다
        print(f"자격증명 획득 실패: {e}", file=sys.stderr)
        return 1

    envelope = _build_envelope(cfg, credentials)

    # --timeout 은 httpx 요청 타임아웃에 적용한다(자격증명 획득은 botocore 자체 타임아웃).
    timeout = cfg.timeout.total_seconds()
    with httpx.Client(timeout=timeout) as http_client:
        client = Client(cfg.server_addr, http_client)
        try:
            result = client.post_auth(envelope)
        except APIError as e:
            print(f"인증 실패: {e}", file=sys.stderr)
            return 1
        except httpx.HTTPError as e:
            print(f"서버 요청 실패: {e}", file=sys.stderr)
            return 1

        print(f"발급 토큰: {result.token}")
        print(f"만료: {result.expires_at.isoformat()}")

        if cfg.verify:
            try:
                claims = client.post_verify(result.token)
            except APIError as e:
                print(f"검증 실패: {e}", file=sys.stderr)
                return 1
            except httpx.HTTPError as e:
                print(f"검증 요청 실패: {e}", file=sys.stderr)
                return 1
            print("검증 클레임:")
            print(f"  iss={claims.issuer}")
            print(f"  sub={claims.subject}")
            print(f"  aud={claims.audience}")
            print(f"  exp={claims.expires_at} iat={claims.issued_at}")
            print(f"  jti={claims.jti} account={claims.account} user_id={claims.user_id}")

    return 0


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
