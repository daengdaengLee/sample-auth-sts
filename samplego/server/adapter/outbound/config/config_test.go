package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// validViper 는 세 정책 값을 모두 채운 viper 를 만든다. 각 테스트는 필요한 키만 바꿔 특정
// 검증 실패나 기본값 폴백을 재현한다.
func validViper() *viper.Viper {
	v := viper.New()
	v.Set("policy.binding_value", "https://server.example/audience")
	v.Set("policy.request_max_age", "3m")
	v.Set("policy.allowed_arns", " arn:aws:iam::123456789012:role/workload , ,arn:aws:iam::123456789012:role/other ")
	return v
}

// loaderViper 는 공유 설정 로더(internal/config)와 동일하게 구성한 viper 를 만든다:
// yaml 파일값을 읽고 AutomaticEnv + 점->밑줄 replacer 를 켠다. validViper 의 viper.Set 은
// 최우선 override 를 직접 주입해 env 해석 경로를 우회하므로, env override 회귀 테스트에는
// 실제 로더 구성을 재현한 이 헬퍼를 쓴다.
func loaderViper(t *testing.T, yamlBody string) *viper.Viper {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(yamlBody)); err != nil {
		t.Fatalf("설정 파싱 실패: %v", err)
	}
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	return v
}

// TestLoad_success 는 세 값이 모두 설정됐을 때 각 getter 가 기대값을 돌려주는지 확인한다.
// allowed_arns 는 앞뒤 공백과 빈 항목이 정리되어 set 에 담긴다.
func TestLoad_success(t *testing.T) {
	cfg, err := Load(validViper())
	if err != nil {
		t.Fatalf("Load() 에러: %v", err)
	}

	if got, want := cfg.ExpectedBinding(), "https://server.example/audience"; got != want {
		t.Errorf("ExpectedBinding()=%q, want %q", got, want)
	}
	if got, want := cfg.MaxAge(), 3*time.Minute; got != want {
		t.Errorf("MaxAge()=%v, want %v", got, want)
	}

	allowed := []string{
		"arn:aws:iam::123456789012:role/workload",
		"arn:aws:iam::123456789012:role/other",
	}
	for _, arn := range allowed {
		if !cfg.IsAllowedARN(arn) {
			t.Errorf("IsAllowedARN(%q)=false, want true", arn)
		}
	}
	if cfg.IsAllowedARN("arn:aws:iam::123456789012:role/nope") {
		t.Error("허용 목록에 없는 ARN 이 true 로 나옴")
	}
	if cfg.IsAllowedARN("") {
		t.Error("빈 ARN 이 true 로 나옴(빈 항목이 set 에 들어감)")
	}
}

// TestLoad_bindingRequired 는 policy.binding_value 가 없으면 에러를 반환하는지 확인한다.
func TestLoad_bindingRequired(t *testing.T) {
	v := validViper()
	v.Set("policy.binding_value", "")
	if _, err := Load(v); err == nil {
		t.Fatal("바인딩 미설정인데 에러가 나지 않음")
	}
}

// TestLoad_maxAgeDefault 는 policy.request_max_age 미설정 시 기본 5m 로 폴백하는지 확인한다.
func TestLoad_maxAgeDefault(t *testing.T) {
	v := validViper()
	v.Set("policy.request_max_age", "")
	v.Set("policy.allowed_arns", "")
	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load() 에러: %v", err)
	}
	if got, want := cfg.MaxAge(), 5*time.Minute; got != want {
		t.Errorf("MaxAge()=%v, want 기본값 %v", got, want)
	}
}

// TestLoad_maxAgeInvalid 는 policy.request_max_age 형식이 잘못되면 에러를 반환하는지 확인한다.
func TestLoad_maxAgeInvalid(t *testing.T) {
	v := validViper()
	v.Set("policy.request_max_age", "5분")
	if _, err := Load(v); err == nil {
		t.Fatal("잘못된 duration 인데 에러가 나지 않음")
	}
}

// TestLoad_maxAgeNonPositive 는 policy.request_max_age 가 0 이하일 때 에러를 반환하는지
// 확인한다(0 이하면 모든 요청이 stale 로 거부되므로 부팅 시점에 막는다).
func TestLoad_maxAgeNonPositive(t *testing.T) {
	for _, raw := range []string{"0", "0s", "-5m"} {
		t.Run(raw, func(t *testing.T) {
			v := validViper()
			v.Set("policy.request_max_age", raw)
			if _, err := Load(v); err == nil {
				t.Fatalf("policy.request_max_age=%q 인데 에러가 나지 않음", raw)
			}
		})
	}
}

// TestLoad_allowedARNsEmpty 는 policy.allowed_arns 가 비면 어떤 ARN 도 허용하지 않는지
// 확인한다.
func TestLoad_allowedARNsEmpty(t *testing.T) {
	v := validViper()
	v.Set("policy.request_max_age", "")
	v.Set("policy.allowed_arns", "   ,  , ")
	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load() 에러: %v", err)
	}
	if cfg.IsAllowedARN("arn:aws:iam::123456789012:role/workload") {
		t.Error("빈 허용 목록인데 ARN 이 허용됨")
	}
}

// TestLoad_envOverride 는 공유 로더 구성(AutomaticEnv + 점->밑줄 replacer)에서 환경변수가
// config.yaml 파일값을 덮어쓰는지 확인한다. 세 정책 키의 override 이름
// (POLICY_BINDING_VALUE / POLICY_REQUEST_MAX_AGE / POLICY_ALLOWED_ARNS)이 실제로 해당 설정
// 키에 연결되는지 잠근다. 키 상수 오타나 replacer 를 통과하지 못하는 키가 생기면 조립 경로에서
// 조용히 깨지는 것을 이 테스트가 잡는다.
func TestLoad_envOverride(t *testing.T) {
	v := loaderViper(t, "policy:\n"+
		"  binding_value: from-file\n"+
		"  request_max_age: 1m\n"+
		"  allowed_arns: arn:aws:iam::123456789012:role/from-file\n")

	t.Setenv("POLICY_BINDING_VALUE", "from-env")
	t.Setenv("POLICY_REQUEST_MAX_AGE", "9m")
	t.Setenv("POLICY_ALLOWED_ARNS", "arn:aws:iam::123456789012:role/from-env")

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load() 에러: %v", err)
	}

	if got, want := cfg.ExpectedBinding(), "from-env"; got != want {
		t.Errorf("ExpectedBinding()=%q, want %q (POLICY_BINDING_VALUE override 미반영)", got, want)
	}
	if got, want := cfg.MaxAge(), 9*time.Minute; got != want {
		t.Errorf("MaxAge()=%v, want %v (POLICY_REQUEST_MAX_AGE override 미반영)", got, want)
	}
	if !cfg.IsAllowedARN("arn:aws:iam::123456789012:role/from-env") {
		t.Error("env 로 지정한 ARN 이 허용되지 않음(POLICY_ALLOWED_ARNS override 미반영)")
	}
	if cfg.IsAllowedARN("arn:aws:iam::123456789012:role/from-file") {
		t.Error("파일값 ARN 이 여전히 허용됨(env 가 파일값을 대체하지 못함)")
	}
}
