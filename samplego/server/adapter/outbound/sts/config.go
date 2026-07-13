package sts

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// keyAllowedEndpoints 는 위임을 허용할 진짜 STS 엔드포인트 목록(README 설정의 "STS
// 엔드포인트 허용 목록", 요청 처리 5단계)의 설정 키다. 쉼표로 구분한 여러 엔드포인트를
// 받으며, 미설정/빈 값이면 아무 엔드포인트도 허용하지 않는다(전부 거부). 서버별로 위임
// 대상을 명시해야 하므로 안전한 기본값을 두지 않는다. 환경변수로 덮어쓸 때는
// STS_ENDPOINT_ALLOWLIST 다(공유 로더가 점을 밑줄로 바꿔 대조). 파일값과 환경변수
// override 의 파싱 의미를 일치시키려고 슬라이스가 아니라 쉼표 문자열로 받는다. 오설정
// 검증(유효 엔드포인트 없음)은 NewVerifier 가 이 패키지 안에서 맡으므로 키는 비공개로 둔다.
const keyAllowedEndpoints = "sts.endpoint_allowlist"

// LoadAllowedEndpoints 는 공유 viper 에서 STS 엔드포인트 허용 목록을 쉼표로 갈라, 앞뒤
// 공백을 다듬고 빈 항목을 버린 정돈된 목록으로 돌려준다. 미설정/빈 값이면 빈 목록이다
// (New 가 받으면 전부 거부). 스킴/포트 정규화와 집합화는 New 의 normalizeEndpoint 가
// 맡으므로 여기서는 정돈만 한다. 조립 지점에서 New 로 넘길 용도다.
func LoadAllowedEndpoints(v *viper.Viper) []string {
	var endpoints []string
	for _, part := range strings.Split(v.GetString(keyAllowedEndpoints), ",") {
		if ep := strings.TrimSpace(part); ep != "" {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints
}

// keyCAFile 은 STS 위임에 쓰는 http.Client 가 추가로 신뢰할 CA(PEM) 파일 경로의 설정 키다.
// 데모 전용 옵션이다: 실 AWS 흐름에서는 시스템 신뢰 저장소로 진짜 STS 를 검증하므로 비워 두고,
// 실 AWS 없이 목 STS(cmd/mocksts)로 로컬 데모를 돌릴 때만 목 STS 가 부팅 때 내보낸 self-signed
// CA 를 여기로 가리킨다. 미설정/빈 값이면 시스템 신뢰 저장소만 쓴다(기존 동작 불변). 환경변수로
// 덮어쓸 때는 STS_CA_FILE 이다(공유 로더가 점을 밑줄로 바꿔 대조).
const keyCAFile = "sts.ca_file"

// LoadCAFile 은 공유 viper 에서 데모 전용 CA 파일 경로를 읽어 앞뒤 공백을 다듬어 돌려준다.
// 미설정/빈 값이면 빈 문자열이다(조립 지점이 이때 CA 주입을 건너뛰고 기본 클라이언트를 쓴다).
func LoadCAFile(v *viper.Viper) string {
	return strings.TrimSpace(v.GetString(keyCAFile))
}

// LoadCAPool 은 PEM CA 파일을 읽어 그 CA 만 담은 x509.CertPool 을 만든다. 조립 지점이 이 풀을
// STS http.Client 의 Transport.TLSClientConfig.RootCAs 로 걸어, "지정한 CA 만 신뢰"하는 표준
// TLS 방식으로 목 STS 의 self-signed 인증서를 신뢰하게 한다(데모 전용). InsecureSkipVerify 는
// 절대 쓰지 않는다: 검증 자체를 끄는 게 아니라 신뢰 앵커에 이 CA 하나만 추가한다. 파일을 못
// 읽거나 유효한 PEM 인증서가 하나도 없으면(AppendCertsFromPEM 실패) 에러를 돌려, 형제 어댑터의
// Load 처럼 오설정을 부팅 시점에 드러낸다.
func LoadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("STS CA 파일(%s) 읽기 실패: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("STS CA 파일(%s)에 유효한 PEM 인증서가 없음", path)
	}
	return pool, nil
}
