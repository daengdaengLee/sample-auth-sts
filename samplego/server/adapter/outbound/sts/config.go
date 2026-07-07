package sts

import (
	"os"
	"strings"
)

// envAllowedEndpoints 는 위임을 허용할 진짜 STS 엔드포인트 목록(README 설정의 "STS
// 엔드포인트 허용 목록", 요청 처리 5단계)이다. 쉼표로 구분한 여러 엔드포인트를 받으며,
// 미설정/빈 값이면 아무 엔드포인트도 허용하지 않는다(전부 거부). 서버별로 위임 대상을
// 명시해야 하므로 안전한 기본값을 두지 않는다.
const envAllowedEndpoints = "STS_ENDPOINT_ALLOWLIST"

// LoadAllowedEndpoints 는 실행 환경에서 STS 엔드포인트 허용 목록을 쉼표로 갈라, 앞뒤
// 공백을 다듬고 빈 항목을 버린 정돈된 목록으로 돌려준다. 미설정/빈 값이면 빈 목록이다
// (New 가 받으면 전부 거부). 스킴/포트 정규화와 집합화는 New 의 normalizeEndpoint 가
// 맡으므로 여기서는 정돈만 한다. 조립 지점에서 New 로 넘길 용도다.
func LoadAllowedEndpoints() []string {
	var endpoints []string
	for _, part := range strings.Split(os.Getenv(envAllowedEndpoints), ",") {
		if ep := strings.TrimSpace(part); ep != "" {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints
}
