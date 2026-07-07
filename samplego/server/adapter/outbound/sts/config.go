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

// LoadAllowedEndpoints 는 실행 환경에서 STS 엔드포인트 허용 목록을 쉼표로 갈라 돌려준다.
// 각 항목의 트리밍/무효 제거/정규화는 New 가 normalizeEndpoint 로 일괄 처리하므로 여기서는
// 나누기만 한다. 미설정이면 [""] 이 되어 New 가 걸러내므로 빈 허용 목록(전부 거부)이 된다.
// main 조립 지점에서 New 로 넘긴다.
func LoadAllowedEndpoints() []string {
	return strings.Split(os.Getenv(envAllowedEndpoints), ",")
}
