package config

import (
	"io"
	"testing"
	"time"
)

// noEnv 는 어떤 환경변수도 설정되지 않은 상태를 흉내낸다(항상 빈 문자열).
func noEnv(string) string { return "" }

// envMap 은 맵 기반 환경 조회 함수를 만든다. 특정 키만 설정된 상태를 테스트로 주입한다.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestParse_defaults 는 인자/환경이 비었을 때 기본값이 서버 config.yaml 과 정렬되는지 확인한다.
func TestParse_defaults(t *testing.T) {
	cfg, err := parse("client", nil, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("parse 실패: %v", err)
	}

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"ServerAddr", cfg.ServerAddr, "http://localhost:8080"},
		{"BindingValue", cfg.BindingValue, "https://server.example/audience"},
		{"STSEndpoint", cfg.STSEndpoint, "https://sts.amazonaws.com"},
		{"Region", cfg.Region, "us-east-1"},
		{"Form", cfg.Form, "header"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if cfg.Verify {
		t.Error("Verify 가 기본 true 임, want false")
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
	}
}

// TestParse_timeout 은 --timeout 이 파싱되고, 형식 오류/0 이하가 거부되는지 확인한다.
func TestParse_timeout(t *testing.T) {
	cfg, err := parse("client", []string{"--timeout", "5s"}, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("parse 실패: %v", err)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", cfg.Timeout)
	}

	if _, err := parse("client", []string{"--timeout", "not-a-duration"}, noEnv, io.Discard); err == nil {
		t.Error("잘못된 timeout 인데 에러가 없음")
	}
	if _, err := parse("client", []string{"--timeout", "0s"}, noEnv, io.Discard); err == nil {
		t.Error("0 timeout 인데 에러가 없음")
	}
	if _, err := parse("client", []string{"--timeout", "-1s"}, noEnv, io.Discard); err == nil {
		t.Error("음수 timeout 인데 에러가 없음")
	}
}

// TestParse_rejectsNonHTTPSEndpoint 는 sts-endpoint 가 https 가 아니거나 host 가 없으면
// 거부되는지 확인한다(서버가 비-https 위임 대상을 거부하므로 로컬에서 먼저 거른다).
func TestParse_rejectsNonHTTPSEndpoint(t *testing.T) {
	cases := []string{"http://sts.amazonaws.com", "ftp://sts.amazonaws.com", "https://", "not-a-url::"}
	for _, ep := range cases {
		if _, err := parse("client", []string{"--sts-endpoint", ep}, noEnv, io.Discard); err == nil {
			t.Errorf("sts-endpoint=%q 인데 통과함", ep)
		}
	}
}

// TestParse_flagOverridesEnv 는 명시된 플래그가 환경변수보다 우선하는지 확인한다.
func TestParse_flagOverridesEnv(t *testing.T) {
	env := envMap(map[string]string{"SERVER_ADDR": "http://from-env:9000"})
	cfg, err := parse("client", []string{"--server-addr", "http://from-flag:1234"}, env, io.Discard)
	if err != nil {
		t.Fatalf("parse 실패: %v", err)
	}
	if cfg.ServerAddr != "http://from-flag:1234" {
		t.Errorf("ServerAddr = %q, want 플래그 값", cfg.ServerAddr)
	}
}

// TestParse_envFallback 은 플래그가 없을 때 환경변수가 기본값을 대체하는지 확인한다.
func TestParse_envFallback(t *testing.T) {
	env := envMap(map[string]string{
		"CLIENT_BINDING_VALUE": "https://other.example/aud",
		"CLIENT_VERIFY":        "true",
	})
	cfg, err := parse("client", nil, env, io.Discard)
	if err != nil {
		t.Fatalf("parse 실패: %v", err)
	}
	if cfg.BindingValue != "https://other.example/aud" {
		t.Errorf("BindingValue = %q, want 환경변수 값", cfg.BindingValue)
	}
	if !cfg.Verify {
		t.Error("Verify = false, want true(CLIENT_VERIFY=true)")
	}
}

// TestParse_rejectsPresigned 는 pre-signed 형태가 후속 미지원으로 거부되는지 확인한다.
func TestParse_rejectsPresigned(t *testing.T) {
	_, err := parse("client", []string{"--form", "presigned"}, noEnv, io.Discard)
	if err == nil {
		t.Fatal("form=presigned 인데 에러가 없음")
	}
}

// TestParse_rejectsUnknownForm 은 알 수 없는 형태를 거부하는지 확인한다.
func TestParse_rejectsUnknownForm(t *testing.T) {
	_, err := parse("client", []string{"--form", "bogus"}, noEnv, io.Discard)
	if err == nil {
		t.Fatal("form=bogus 인데 에러가 없음")
	}
}

// TestParse_staticCredsRequireKeys 는 static 모드에서 키가 빠지면 거부하는지 확인한다.
func TestParse_staticCredsRequireKeys(t *testing.T) {
	_, err := parse("client", []string{"--static-creds"}, noEnv, io.Discard)
	if err == nil {
		t.Fatal("static-creds 인데 키 없이 통과함")
	}

	cfg, err := parse("client", []string{
		"--static-creds",
		"--static-access-key-id", "AKID",
		"--static-secret-key", "secret",
	}, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("static 키를 줬는데 실패: %v", err)
	}
	if !cfg.StaticCreds || cfg.StaticAccessKeyID != "AKID" || cfg.StaticSecretKey != "secret" {
		t.Errorf("static 설정이 올바로 채워지지 않음: %+v", cfg)
	}
}

// TestParse_rejectsEmptyRequired 는 빈 필수값(예: 빈 server-addr)을 거부하는지 확인한다.
func TestParse_rejectsEmptyRequired(t *testing.T) {
	_, err := parse("client", []string{"--server-addr", ""}, noEnv, io.Discard)
	if err == nil {
		t.Fatal("빈 server-addr 인데 통과함")
	}
}
