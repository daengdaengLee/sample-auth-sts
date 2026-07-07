package issuer

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

// validViper 는 네 값을 모두 채운 viper 를 만든다. 각 테스트는 필요한 키만 바꿔 특정 검증
// 실패를 재현한다. secret 은 최소 길이(32바이트)를 넘긴다.
func validViper() *viper.Viper {
	v := viper.New()
	v.Set("jwt.signing_secret", "0123456789abcdef0123456789abcdef") // 32바이트
	v.Set("jwt.ttl", "10m")
	v.Set("jwt.issuer", "https://server.example")
	v.Set("jwt.audience", "https://server.example/clients")
	return v
}

// TestLoad_success 는 네 값이 모두 있을 때 Params 로 그대로 담기는지 확인한다.
func TestLoad_success(t *testing.T) {
	p, err := Load(validViper())
	if err != nil {
		t.Fatalf("Load() 에러: %v", err)
	}
	if got, want := string(p.Secret), "0123456789abcdef0123456789abcdef"; got != want {
		t.Errorf("Secret=%q, want %q", got, want)
	}
	if got, want := p.TTL, 10*time.Minute; got != want {
		t.Errorf("TTL=%v, want %v", got, want)
	}
	if got, want := p.Issuer, "https://server.example"; got != want {
		t.Errorf("Issuer=%q, want %q", got, want)
	}
	if got, want := p.Audience, "https://server.example/clients"; got != want {
		t.Errorf("Audience=%q, want %q", got, want)
	}
}

// TestLoad_secretRequired 는 시크릿이 비면 에러를 반환하는지 확인한다.
func TestLoad_secretRequired(t *testing.T) {
	v := validViper()
	v.Set("jwt.signing_secret", "")
	if _, err := Load(v); err == nil {
		t.Fatal("시크릿 미설정인데 에러가 나지 않음")
	}
}

// TestLoad_secretTooShort 는 32바이트 미만 시크릿이면 에러를 반환하는지 확인한다(약한 키 차단).
func TestLoad_secretTooShort(t *testing.T) {
	v := validViper()
	v.Set("jwt.signing_secret", "too-short-secret") // 16바이트
	if _, err := Load(v); err == nil {
		t.Fatal("32바이트 미만 시크릿인데 에러가 나지 않음")
	}
}

// TestLoad_ttlDefault 는 jwt.ttl 미설정 시 기본 15m 로 폴백하는지 확인한다.
func TestLoad_ttlDefault(t *testing.T) {
	v := validViper()
	v.Set("jwt.ttl", "")
	p, err := Load(v)
	if err != nil {
		t.Fatalf("Load() 에러: %v", err)
	}
	if got, want := p.TTL, 15*time.Minute; got != want {
		t.Errorf("TTL=%v, want 기본값 %v", got, want)
	}
}

// TestLoad_ttlInvalid 는 jwt.ttl 형식이 잘못되면 에러를 반환하는지 확인한다.
func TestLoad_ttlInvalid(t *testing.T) {
	v := validViper()
	v.Set("jwt.ttl", "15분")
	if _, err := Load(v); err == nil {
		t.Fatal("잘못된 duration 인데 에러가 나지 않음")
	}
}

// TestLoad_ttlNonPositive 는 jwt.ttl 이 0 이하면 에러를 반환하는지 확인한다.
func TestLoad_ttlNonPositive(t *testing.T) {
	for _, raw := range []string{"0", "0s", "-1m"} {
		t.Run(raw, func(t *testing.T) {
			v := validViper()
			v.Set("jwt.ttl", raw)
			if _, err := Load(v); err == nil {
				t.Fatalf("jwt.ttl=%q 인데 에러가 나지 않음", raw)
			}
		})
	}
}

// TestLoad_issuerRequired 는 issuer 가 비면 에러를 반환하는지 확인한다.
func TestLoad_issuerRequired(t *testing.T) {
	v := validViper()
	v.Set("jwt.issuer", "")
	if _, err := Load(v); err == nil {
		t.Fatal("issuer 미설정인데 에러가 나지 않음")
	}
}

// TestLoad_audienceRequired 는 audience 가 비면 에러를 반환하는지 확인한다.
func TestLoad_audienceRequired(t *testing.T) {
	v := validViper()
	v.Set("jwt.audience", "")
	if _, err := Load(v); err == nil {
		t.Fatal("audience 미설정인데 에러가 나지 않음")
	}
}
