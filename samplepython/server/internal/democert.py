"""로컬 데모 전용 self-signed TLS 인증서 생성.

목 STS 커맨드(cmd/mocksts)가 부팅 때 이 인증서로 TLS 를 서빙하고, 같은 인증서(PEM)를 신뢰
앵커(CA)로 내보내 서버가 sts.ca_file 로 신뢰하게 한다. 이렇게 하면 실 AWS 없이 server -> 목 STS
구간의 TLS 신뢰를 이을 수 있다.

이 인증서는 오로지 데모 전용이며 실 배포에서는 절대 쓰지 말 것. 매 실행마다 새로 생성되므로
커밋된 비밀이 없다. self-signed 라 인증서 자체가 루트(CA)이므로, 돌려준 cert_pem 을 그대로 서버
신뢰 앵커로 넣으면 이 인증서로 서빙하는 TLS 를 신뢰할 수 있다.
"""

from __future__ import annotations

import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# 데모 인증서 유효 기간. 데모 실행 동안만 유효하면 되므로 짧게 잡되, 시계 오차를 감안해 하루
# 정도 여유를 둔다.
_CERT_VALIDITY = datetime.timedelta(hours=24)


def generate(hosts: list[str]) -> tuple[bytes, bytes]:
    """주어진 host 목록(DNS 이름 또는 IP 문자열)을 SAN 에 담은 self-signed 인증서를 만들어
    (cert_pem, key_pem) 을 돌려준다. TLS 검증은 접속에 쓴 호스트가 SAN 에 있어야 통과하므로
    (InsecureSkipVerify 를 쓰지 않는다), 데모에서 접속할 이름(예: localhost, 127.0.0.1)을 모두
    넣어야 한다.
    """

    key = ec.generate_private_key(ec.SECP256R1())

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "samplepython-mocksts-demo")])

    sans: list[x509.GeneralName] = []
    for h in hosts:
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            sans.append(x509.DNSName(h))
        else:
            sans.append(x509.IPAddress(ip))

    # 시계 오차를 감안해 시작을 약간 과거로 당긴다.
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + _CERT_VALIDITY)
        # self-signed 인증서를 신뢰 앵커로도 쓰므로 CA 로 표시한다.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem
