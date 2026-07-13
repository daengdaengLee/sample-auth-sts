package democert

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestGenerate 는 생성 결과가 파싱 가능한 self-signed 인증서이고, 요청한 host 가 SAN 에 담기며,
// 돌려준 인증서 PEM 이 CertPool 에 신뢰 앵커로 append 되는지 확인한다(서버 RootCAs 로 쓰이는
// 경로와 같다).
func TestGenerate(t *testing.T) {
	tlsCert, certPEM, err := Generate([]string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("Generate 실패: %v", err)
	}

	// TLS 서빙에 쓸 인증서/키 쌍이 실제로 구성됐는지(빈 Certificate 가 아닌지) 본다.
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("tls.Certificate 에 인증서가 없음")
	}

	// PEM 을 파싱해 self-signed(Subject == Issuer)이고 SAN 에 데모 호스트가 들었는지 확인한다.
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("certPEM 이 CERTIFICATE 블록이 아님: %+v", block)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("인증서 파싱 실패: %v", err)
	}
	if cert.Subject.String() != cert.Issuer.String() {
		t.Errorf("self-signed 아님: subject=%q issuer=%q", cert.Subject, cert.Issuer)
	}
	if !cert.IsCA {
		t.Error("IsCA=false, want true(신뢰 앵커로 써야 함)")
	}

	hasDNS := false
	for _, n := range cert.DNSNames {
		if n == "localhost" {
			hasDNS = true
		}
	}
	if !hasDNS {
		t.Errorf("DNSNames 에 localhost 없음: %v", cert.DNSNames)
	}
	hasIP := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			hasIP = true
		}
	}
	if !hasIP {
		t.Errorf("IPAddresses 에 127.0.0.1 없음: %v", cert.IPAddresses)
	}

	// 서버 RootCAs 로 쓰이는 것과 같은 방식으로 신뢰 앵커에 append 되는지 확인한다.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Error("certPEM 을 CertPool 에 append 하지 못함")
	}
}
