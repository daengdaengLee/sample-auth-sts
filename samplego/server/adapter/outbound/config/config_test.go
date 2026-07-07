package config

import (
	"testing"
	"time"
)

// TestLoad_success 는 세 환경변수가 모두 설정됐을 때 각 getter 가 기대값을 돌려주는지
// 확인한다. ALLOWED_ARNS 는 앞뒤 공백과 빈 항목이 정리되어 set 에 담긴다.
func TestLoad_success(t *testing.T) {
	t.Setenv("SERVER_BINDING_VALUE", "https://server.example/audience")
	t.Setenv("REQUEST_MAX_AGE", "3m")
	t.Setenv("ALLOWED_ARNS", " arn:aws:iam::123456789012:role/workload , ,arn:aws:iam::123456789012:role/other ")

	cfg, err := Load()
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

// TestLoad_bindingRequired 는 SERVER_BINDING_VALUE 가 없으면 에러를 반환하는지 확인한다.
func TestLoad_bindingRequired(t *testing.T) {
	t.Setenv("SERVER_BINDING_VALUE", "")
	t.Setenv("REQUEST_MAX_AGE", "3m")
	t.Setenv("ALLOWED_ARNS", "arn:aws:iam::123456789012:role/workload")

	if _, err := Load(); err == nil {
		t.Fatal("바인딩 미설정인데 에러가 나지 않음")
	}
}

// TestLoad_maxAgeDefault 는 REQUEST_MAX_AGE 미설정 시 기본 5m 로 폴백하는지 확인한다.
func TestLoad_maxAgeDefault(t *testing.T) {
	t.Setenv("SERVER_BINDING_VALUE", "https://server.example/audience")
	t.Setenv("REQUEST_MAX_AGE", "")
	t.Setenv("ALLOWED_ARNS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() 에러: %v", err)
	}
	if got, want := cfg.MaxAge(), 5*time.Minute; got != want {
		t.Errorf("MaxAge()=%v, want 기본값 %v", got, want)
	}
}

// TestLoad_maxAgeInvalid 는 REQUEST_MAX_AGE 형식이 잘못되면 에러를 반환하는지 확인한다.
func TestLoad_maxAgeInvalid(t *testing.T) {
	t.Setenv("SERVER_BINDING_VALUE", "https://server.example/audience")
	t.Setenv("REQUEST_MAX_AGE", "5분")
	t.Setenv("ALLOWED_ARNS", "")

	if _, err := Load(); err == nil {
		t.Fatal("잘못된 duration 인데 에러가 나지 않음")
	}
}

// TestLoad_maxAgeNonPositive 는 REQUEST_MAX_AGE 가 0 이하일 때 에러를 반환하는지
// 확인한다(0 이하면 모든 요청이 stale 로 거부되므로 부팅 시점에 막는다).
func TestLoad_maxAgeNonPositive(t *testing.T) {
	for _, v := range []string{"0", "0s", "-5m"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("SERVER_BINDING_VALUE", "https://server.example/audience")
			t.Setenv("REQUEST_MAX_AGE", v)
			t.Setenv("ALLOWED_ARNS", "")
			if _, err := Load(); err == nil {
				t.Fatalf("REQUEST_MAX_AGE=%q 인데 에러가 나지 않음", v)
			}
		})
	}
}

// TestLoad_allowedARNsEmpty 는 ALLOWED_ARNS 가 비면 어떤 ARN 도 허용하지 않는지 확인한다.
func TestLoad_allowedARNsEmpty(t *testing.T) {
	t.Setenv("SERVER_BINDING_VALUE", "https://server.example/audience")
	t.Setenv("REQUEST_MAX_AGE", "")
	t.Setenv("ALLOWED_ARNS", "   ,  , ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() 에러: %v", err)
	}
	if cfg.IsAllowedARN("arn:aws:iam::123456789012:role/workload") {
		t.Error("빈 허용 목록인데 ARN 이 허용됨")
	}
}
