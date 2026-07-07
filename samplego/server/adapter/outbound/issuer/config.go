package issuer

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

const (
	// keySecret 은 HS256 서명 대칭키의 설정 키다. 서버별 고유값이라 안전한 기본값이 없어
	// 필수로 둔다. 커밋된 샘플 값은 배포에서 반드시 override 해야 한다(config.yaml 주석 참고).
	keySecret = "jwt.signing_secret"

	// keyTTL 은 발급 토큰 유효 기간의 설정 키다. time.ParseDuration 형식("15m" 등)으로 받으며,
	// 미설정 시 defaultTTL 로 폴백한다.
	keyTTL = "jwt.ttl"

	// keyIssuer 는 발급자 식별자(iss 클레임)의 설정 키다. 서버별 고유값이라 필수로 둔다.
	keyIssuer = "jwt.issuer"

	// keyAudience 는 발급 토큰 대상 식별자(aud 클레임)의 설정 키다. 서버별 고유값이라 필수로 둔다.
	keyAudience = "jwt.audience"

	// defaultTTL 은 jwt.ttl 이 설정되지 않았을 때 쓰는 기본 유효 기간이다.
	defaultTTL = 15 * time.Minute

	// minSecretBytes 는 HS256 서명키의 최소 길이다. 256비트 미만의 약한 키는 서명 위조
	// 위험이 있어 부팅 시점에 막는다.
	minSecretBytes = 32
)

// Params 는 config.yaml 의 jwt 섹션에서 로드한 발급 설정 운반자다. New 로 넘겨 Issuer 를
// 만든다. port 를 구현하는 것은 Issuer 이고, 이 타입은 조립용 값 운반자다.
type Params struct {
	Secret   []byte
	TTL      time.Duration
	Issuer   string
	Audience string
}

// Load 는 공유 viper 에서 jwt 섹션을 읽어 검증한다. 오설정(약한/미설정 키, 잘못된 TTL,
// 미설정 issuer/audience)은 에러로 돌려 부팅 시점에 드러낸다(config 어댑터 Load 의 부팅
// 게이트 관례와 동일 톤). 주입받은 v 로 테스트에서 값을 넣기 쉽다.
func Load(v *viper.Viper) (Params, error) {
	secret := v.GetString(keySecret)
	if secret == "" {
		return Params{}, fmt.Errorf("설정 %s 가 비어 있음(HS256 서명키 필요)", keySecret)
	}
	if len(secret) < minSecretBytes {
		return Params{}, fmt.Errorf("설정 %s 가 너무 짧음(현재 %d바이트, 최소 %d바이트): 약한 키는 서명 위조 위험", keySecret, len(secret), minSecretBytes)
	}

	ttl := defaultTTL
	if raw := v.GetString(keyTTL); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Params{}, fmt.Errorf("설정 %s 파싱 실패(%q): %w", keyTTL, raw, err)
		}
		ttl = d
	}
	if ttl <= 0 {
		return Params{}, fmt.Errorf("설정 %s 는 양수여야 함(현재 %v): 0 이하면 발급 즉시 만료된 토큰이 나옴", keyTTL, ttl)
	}

	issuer := v.GetString(keyIssuer)
	if issuer == "" {
		return Params{}, fmt.Errorf("설정 %s 가 비어 있음(발급자 식별자 필요)", keyIssuer)
	}

	audience := v.GetString(keyAudience)
	if audience == "" {
		return Params{}, fmt.Errorf("설정 %s 가 비어 있음(대상 식별자 필요)", keyAudience)
	}

	return Params{
		Secret:   []byte(secret),
		TTL:      ttl,
		Issuer:   issuer,
		Audience: audience,
	}, nil
}
