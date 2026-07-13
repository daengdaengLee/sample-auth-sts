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

// TestParse_regionEndpointConsistency 는 표준 STS 호스트에서 파생한 리전과 서명 리전의
// 정합성 검사를 확인한다: 일치/커스텀 호스트는 통과, 불일치는 거부.
func TestParse_regionEndpointConsistency(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		region   string
		wantErr  bool
	}{
		{"global + us-east-1(기본)", "https://sts.amazonaws.com", "us-east-1", false},
		{"global + eu-west-1(불일치)", "https://sts.amazonaws.com", "eu-west-1", true},
		{"리전형 + 일치", "https://sts.eu-west-1.amazonaws.com", "eu-west-1", false},
		{"리전형 + 불일치", "https://sts.eu-west-1.amazonaws.com", "us-east-1", true},
		{"fips 리전형 + 일치", "https://sts-fips.us-east-1.amazonaws.com", "us-east-1", false},
		{"cn 리전형 + 일치", "https://sts.cn-north-1.amazonaws.com.cn", "cn-north-1", false},
		{"cn 리전형 + 불일치", "https://sts.cn-north-1.amazonaws.com.cn", "us-east-1", true},
		{"dualstack + 일치", "https://sts.eu-west-1.api.aws", "eu-west-1", false},
		{"dualstack + 불일치", "https://sts.eu-west-1.api.aws", "us-east-1", true},
		{"커스텀 호스트는 스킵", "https://sts.internal.example", "us-east-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse("client", []string{"--sts-endpoint", tc.endpoint, "--region", tc.region}, noEnv, io.Discard)
			if tc.wantErr && err == nil {
				t.Errorf("endpoint=%q region=%q: 에러 기대했으나 통과함", tc.endpoint, tc.region)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("endpoint=%q region=%q: 통과 기대했으나 에러: %v", tc.endpoint, tc.region, err)
			}
		})
	}
}

// TestParse_regionEndpointDerivation 은 한쪽만 명시됐을 때 다른 쪽을 파생해 기본 충돌을
// 없애는지 확인한다(양쪽 기본이 독립 소스라 생기던 하드 거부 제거).
func TestParse_regionEndpointDerivation(t *testing.T) {
	t.Run("AWS_REGION 만(env) -> 엔드포인트 파생", func(t *testing.T) {
		cfg, err := parse("client", nil, envMap(map[string]string{"AWS_REGION": "eu-west-1"}), io.Discard)
		if err != nil {
			t.Fatalf("parse 실패: %v", err)
		}
		if cfg.Region != "eu-west-1" {
			t.Errorf("Region = %q, want eu-west-1", cfg.Region)
		}
		if cfg.STSEndpoint != "https://sts.eu-west-1.amazonaws.com" {
			t.Errorf("STSEndpoint = %q, want 파생된 리전형", cfg.STSEndpoint)
		}
	})

	t.Run("--region 만 -> 엔드포인트 파생", func(t *testing.T) {
		cfg, err := parse("client", []string{"--region", "ap-northeast-2"}, noEnv, io.Discard)
		if err != nil {
			t.Fatalf("parse 실패: %v", err)
		}
		if cfg.STSEndpoint != "https://sts.ap-northeast-2.amazonaws.com" {
			t.Errorf("STSEndpoint = %q", cfg.STSEndpoint)
		}
	})

	t.Run("--region us-east-1 만 -> global 유지", func(t *testing.T) {
		cfg, err := parse("client", []string{"--region", "us-east-1"}, noEnv, io.Discard)
		if err != nil {
			t.Fatalf("parse 실패: %v", err)
		}
		if cfg.STSEndpoint != "https://sts.amazonaws.com" {
			t.Errorf("STSEndpoint = %q, want global", cfg.STSEndpoint)
		}
	})

	t.Run("--sts-endpoint 리전형 만 -> 리전 파생", func(t *testing.T) {
		cfg, err := parse("client", []string{"--sts-endpoint", "https://sts.eu-west-1.amazonaws.com"}, noEnv, io.Discard)
		if err != nil {
			t.Fatalf("parse 실패: %v", err)
		}
		if cfg.Region != "eu-west-1" {
			t.Errorf("Region = %q, want eu-west-1(파생)", cfg.Region)
		}
	})

	t.Run("cn 리전 만 -> 미파생, validate 불일치로 거부", func(t *testing.T) {
		if _, err := parse("client", nil, envMap(map[string]string{"AWS_REGION": "cn-north-1"}), io.Discard); err == nil {
			t.Error("cn 리전 + 기본 global 인데 통과함(엔드포인트 명시 요구여야 함)")
		}
	})

	// 플래그가 ambient env 를 이긴다(엔드포인트 축): AWS_REGION(env)와 다른 리전형 엔드포인트를
	// 플래그로 주면, ambient 리전을 무시하고 엔드포인트에서 리전을 파생해 통과한다.
	t.Run("--sts-endpoint 플래그가 ambient AWS_REGION 을 이김", func(t *testing.T) {
		cfg, err := parse("client",
			[]string{"--sts-endpoint", "https://sts.eu-west-1.amazonaws.com"},
			envMap(map[string]string{"AWS_REGION": "us-east-1"}), io.Discard)
		if err != nil {
			t.Fatalf("parse 실패: %v", err)
		}
		if cfg.Region != "eu-west-1" {
			t.Errorf("Region = %q, want eu-west-1(플래그 엔드포인트에서 파생)", cfg.Region)
		}
	})

	// 플래그가 ambient env 를 이긴다(리전 축, 대칭): STS_ENDPOINT(env)가 global 이어도 리전을
	// 플래그로 주면, ambient 엔드포인트를 무시하고 리전에서 엔드포인트를 파생해 통과한다.
	t.Run("--region 플래그가 ambient STS_ENDPOINT 를 이김", func(t *testing.T) {
		cfg, err := parse("client",
			[]string{"--region", "eu-west-1"},
			envMap(map[string]string{"STS_ENDPOINT": "https://sts.amazonaws.com"}), io.Discard)
		if err != nil {
			t.Fatalf("parse 실패: %v", err)
		}
		if cfg.STSEndpoint != "https://sts.eu-west-1.amazonaws.com" {
			t.Errorf("STSEndpoint = %q, want 리전 플래그에서 파생", cfg.STSEndpoint)
		}
	})
}

// TestParse_rejectsMalformedRegion 은 리전답지 않은 문자열이 로컬 형식 에러로 거부되고, 정상
// 리전 형태(표준/gov)는 통과하는지 확인한다.
func TestParse_rejectsMalformedRegion(t *testing.T) {
	bad := []string{"garbage", "eu_west_1", "EU-WEST-1", "eu-west", "", "us east 1"}
	for _, r := range bad {
		if _, err := parse("client", []string{"--region", r}, noEnv, io.Discard); err == nil {
			t.Errorf("region=%q 인데 통과함(형식 에러 기대)", r)
		}
	}
	good := []string{"us-east-1", "eu-west-1", "ap-northeast-2", "us-gov-west-1"}
	for _, r := range good {
		if _, err := parse("client", []string{"--region", r}, noEnv, io.Discard); err != nil {
			t.Errorf("region=%q 인데 거부됨: %v", r, err)
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

// TestParse_acceptsPresigned 는 pre-signed 형태가 수락되고 기본 만료(5m)가 반영되는지 확인한다.
func TestParse_acceptsPresigned(t *testing.T) {
	cfg, err := parse("client", []string{"--form", "presigned"}, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("form=presigned 인데 에러: %v", err)
	}
	if cfg.Form != "presigned" {
		t.Errorf("Form = %q, want presigned", cfg.Form)
	}
	if cfg.PresignExpiry != 5*time.Minute {
		t.Errorf("PresignExpiry = %v, want 5m(기본)", cfg.PresignExpiry)
	}
}

// TestParse_presignExpiry 는 --presign-expiry 가 파싱되고, 형식 오류와 presigned 에서의 0 이하가
// 거부되는지 확인한다. header 형태에서는 만료 값이 검증되지 않는다(형태별 처리).
func TestParse_presignExpiry(t *testing.T) {
	cfg, err := parse("client", []string{"--form", "presigned", "--presign-expiry", "90s"}, noEnv, io.Discard)
	if err != nil {
		t.Fatalf("parse 실패: %v", err)
	}
	if cfg.PresignExpiry != 90*time.Second {
		t.Errorf("PresignExpiry = %v, want 90s", cfg.PresignExpiry)
	}

	if _, err := parse("client", []string{"--form", "presigned", "--presign-expiry", "not-a-duration"}, noEnv, io.Discard); err == nil {
		t.Error("잘못된 presign-expiry 인데 에러가 없음")
	}
	if _, err := parse("client", []string{"--form", "presigned", "--presign-expiry", "0s"}, noEnv, io.Discard); err == nil {
		t.Error("presigned + 0 만료인데 에러가 없음")
	}
	if _, err := parse("client", []string{"--form", "presigned", "--presign-expiry", "-1s"}, noEnv, io.Discard); err == nil {
		t.Error("presigned + 음수 만료인데 에러가 없음")
	}
	// X-Amz-Expires 는 초 단위 정수라 1초 미만은 0 으로 잘려 서버가 거부하므로 로컬에서 미리 거른다.
	if _, err := parse("client", []string{"--form", "presigned", "--presign-expiry", "500ms"}, noEnv, io.Discard); err == nil {
		t.Error("presigned + 1초 미만 만료인데 에러가 없음(0 으로 잘림)")
	}
	// 소수 초(1.5s)도 조용히 잘리므로 거부한다(초 단위 강제).
	if _, err := parse("client", []string{"--form", "presigned", "--presign-expiry", "1500ms"}, noEnv, io.Discard); err == nil {
		t.Error("presigned + 소수 초 만료인데 에러가 없음(초 단위로 잘림)")
	}
	// 상한(7일) 초과는 서버가 거부하므로 로컬에서 미리 거른다(200h = 7일 초과).
	if _, err := parse("client", []string{"--form", "presigned", "--presign-expiry", "200h"}, noEnv, io.Discard); err == nil {
		t.Error("presigned + 상한 초과 만료인데 에러가 없음(200h > 7일)")
	}
	// 상한 경계(정확히 7일)는 통과해야 한다.
	if _, err := parse("client", []string{"--form", "presigned", "--presign-expiry", "168h"}, noEnv, io.Discard); err != nil {
		t.Errorf("presigned + 정확히 7일(168h) 만료인데 거부됨: %v", err)
	}

	// header 형태는 만료가 무의미하므로 0 이하/소수 초여도 통과해야 한다(형태별 처리).
	if _, err := parse("client", []string{"--form", "header", "--presign-expiry", "0s"}, noEnv, io.Discard); err != nil {
		t.Errorf("header 형태인데 만료 0 으로 거부됨: %v", err)
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
