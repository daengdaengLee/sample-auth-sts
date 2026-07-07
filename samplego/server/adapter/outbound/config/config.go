// Package config 는 README 헥사고날 설계의 "설정 어댑터(아웃바운드 어댑터)"다.
// 실행 환경(환경변수)에서 서버 정책 값을 읽어 도메인 코어의 Policy 아웃바운드
// 포트를 구현한다. 코어가 실제로 판단에 쓰는 값(바인딩 기대값, 최대 age, 허용 ARN
// 목록)만 노출한다. STS 엔드포인트 허용 목록/리전은 코어가 쓰지 않고 STS 신원 검증
// 어댑터가 경계에서 강제하므로 여기 두지 않는다(인터페이스 분리, domain/outbound.go 참고).
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

const (
	// envBindingValue 는 이 서버만 받아들이는 고유 바인딩 기대값(2단계 검증 대상)이다.
	// 서버별 고유값이라 안전한 기본값이 없으므로 필수로 둔다.
	envBindingValue = "SERVER_BINDING_VALUE"

	// envRequestMaxAge 는 받아들일 서명 요청의 최대 age(4단계)다. time.ParseDuration
	// 형식("5m", "90s" 등)으로 받으며, 미설정 시 defaultMaxAge 로 폴백한다.
	envRequestMaxAge = "REQUEST_MAX_AGE"

	// envAllowedARNs 는 STS 가 돌려준 ARN 을 대조할 허용 신원 목록(7단계)이다. 쉼표로
	// 구분한 여러 ARN 을 받으며, 미설정/빈 값이면 아무 ARN 도 허용하지 않는다.
	envAllowedARNs = "ALLOWED_ARNS"

	// defaultMaxAge 는 REQUEST_MAX_AGE 가 설정되지 않았을 때 쓰는 기본 최대 age 다.
	defaultMaxAge = 5 * time.Minute
)

// Config 는 환경변수에서 로드한 서버 정책 값을 담고 도메인 Policy 포트를 구현한다.
// 필드는 불변으로 다루며 접근은 메서드로만 한다.
type Config struct {
	binding     string
	maxAge      time.Duration
	allowedARNs map[string]bool
}

// Load 는 환경변수에서 정책 값을 읽어 Config 를 만든다. SERVER_BINDING_VALUE 가
// 비었거나 REQUEST_MAX_AGE 형식이 잘못되면 에러를 반환해 부팅 시점에 오설정을
// 빨리 드러낸다.
func Load() (*Config, error) {
	binding := os.Getenv(envBindingValue)
	if binding == "" {
		return nil, fmt.Errorf("환경변수 %s 가 설정되지 않음(서버별 고유 바인딩 기대값 필요)", envBindingValue)
	}

	maxAge := defaultMaxAge
	if v := os.Getenv(envRequestMaxAge); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("환경변수 %s 파싱 실패(%q): %w", envRequestMaxAge, v, err)
		}
		maxAge = d
	}
	if maxAge <= 0 {
		return nil, fmt.Errorf("환경변수 %s 는 양수여야 함(현재 %v): 0 이하면 모든 요청이 거부됨", envRequestMaxAge, maxAge)
	}

	return &Config{
		binding:     binding,
		maxAge:      maxAge,
		allowedARNs: parseARNs(os.Getenv(envAllowedARNs)),
	}, nil
}

// parseARNs 는 쉼표로 구분한 ARN 목록 문자열을 set 으로 만든다. 각 항목의 앞뒤
// 공백을 다듬고 빈 항목은 버린다. 빈 문자열이면 빈 set 을 돌려준다(전부 거부).
func parseARNs(raw string) map[string]bool {
	set := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		if arn := strings.TrimSpace(part); arn != "" {
			set[arn] = true
		}
	}
	return set
}

// ExpectedBinding 은 이 서버만 받아들이는 고유 바인딩 기대값이다(2단계).
func (c *Config) ExpectedBinding() string {
	return c.binding
}

// MaxAge 는 받아들일 서명 요청의 최대 age 다(4단계).
func (c *Config) MaxAge() time.Duration {
	return c.maxAge
}

// IsAllowedARN 은 STS 가 돌려준 ARN 이 허용 신원 목록에 드는지 대조한다(7단계).
func (c *Config) IsAllowedARN(arn string) bool {
	return c.allowedARNs[arn]
}

// 컴파일 타임에 Config 가 아웃바운드 포트를 만족하는지 확인한다.
var _ domain.Policy = (*Config)(nil)
