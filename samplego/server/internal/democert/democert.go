// Package democert 는 로컬 데모 전용 self-signed TLS 인증서를 즉석에서 생성한다. 목 STS
// 커맨드(cmd/mocksts)가 부팅 때 이 인증서로 TLS 를 서빙하고, 같은 인증서(PEM)를 신뢰 앵커(CA)로
// 내보내 서버가 sts.ca_file 로 신뢰하게 한다. 이렇게 하면 실 AWS 없이 server -> 목 STS 구간의
// TLS 신뢰를 이을 수 있다.
//
// 이 인증서는 오로지 데모 전용이며 실 배포에서는 절대 쓰지 말 것. 개인키는 호출부가 메모리에서만
// 쓰고 디스크에 남기지 않으며, 매 실행마다 새로 생성되므로 커밋된 비밀이 없다. 표준 라이브러리만
// 쓴다(AWS SDK 도입 없음).
package democert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// certValidity 는 데모 인증서의 유효 기간이다. 데모 실행 동안만 유효하면 되므로 짧게 잡되,
// 시계 오차(약간 미래/과거)를 감안해 하루 정도 여유를 둔다.
const certValidity = 24 * time.Hour

// Generate 는 주어진 host 목록(DNS 이름 또는 IP 문자열)을 SAN 에 담은 self-signed 인증서를
// 만들어, TLS 서빙용 tls.Certificate 와 신뢰 앵커로 내보낼 인증서 PEM 을 함께 돌려준다.
// self-signed 라 이 인증서 자체가 루트(CA)이므로, 돌려준 certPEM 을 그대로 서버 RootCAs 에
// 넣으면 이 인증서로 서빙하는 TLS 를 신뢰할 수 있다(데모 전용).
//
// host 문자열이 IP 로 파싱되면 SAN 의 IPAddresses 에, 아니면 DNSNames 에 넣는다. TLS 검증은
// 접속에 쓴 호스트가 SAN 에 있어야 통과하므로(InsecureSkipVerify 를 쓰지 않는다), 데모에서
// 접속할 이름(예: localhost, 127.0.0.1)을 모두 넣어야 한다.
func Generate(hosts []string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("데모 키 생성 실패: %w", err)
	}

	// 시리얼 번호는 128비트 난수로 뽑는다(고정값 충돌 회피).
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("데모 시리얼 생성 실패: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "samplego-mocksts-demo"},
		// 시계 오차를 감안해 시작을 약간 과거로 당긴다.
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// self-signed 인증서를 신뢰 앵커로도 쓰므로 CA 로 표시한다.
		IsCA: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("데모 인증서 생성 실패: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("데모 키 마샬 실패: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("데모 인증서/키 쌍 구성 실패: %w", err)
	}

	return tlsCert, certPEM, nil
}
