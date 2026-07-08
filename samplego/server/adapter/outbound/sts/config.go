package sts

import (
	"strings"

	"github.com/spf13/viper"
)

// keyAllowedEndpoints 는 위임을 허용할 진짜 STS 엔드포인트 목록(README 설정의 "STS
// 엔드포인트 허용 목록", 요청 처리 5단계)의 설정 키다. 쉼표로 구분한 여러 엔드포인트를
// 받으며, 미설정/빈 값이면 아무 엔드포인트도 허용하지 않는다(전부 거부). 서버별로 위임
// 대상을 명시해야 하므로 안전한 기본값을 두지 않는다. 환경변수로 덮어쓸 때는
// STS_ENDPOINT_ALLOWLIST 다(공유 로더가 점을 밑줄로 바꿔 대조). 파일값과 환경변수
// override 의 파싱 의미를 일치시키려고 슬라이스가 아니라 쉼표 문자열로 받는다.
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
