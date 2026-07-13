package sts

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/viper"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/config/configtest"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/democert"
)

// TestLoadAllowedEndpoints_success 는 sts.endpoint_allowlist 를 쉼표로 갈라 앞뒤 공백과
// 빈 항목을 정리한 목록으로 돌려주는지 확인한다.
func TestLoadAllowedEndpoints_success(t *testing.T) {
	v := viper.New()
	v.Set("sts.endpoint_allowlist", " https://sts.amazonaws.com , ,https://sts.us-east-1.amazonaws.com ")

	got := LoadAllowedEndpoints(v)
	want := []string{
		"https://sts.amazonaws.com",
		"https://sts.us-east-1.amazonaws.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LoadAllowedEndpoints()=%v, want %v", got, want)
	}
}

// TestLoadAllowedEndpoints_empty 는 미설정/빈 값이면 빈 목록을 돌려주는지 확인한다
// (New 가 받으면 전부 거부).
func TestLoadAllowedEndpoints_empty(t *testing.T) {
	for name, raw := range map[string]string{
		"미설정": "",
		"공백뿐": "   ,  , ",
	} {
		t.Run(name, func(t *testing.T) {
			v := viper.New()
			v.Set("sts.endpoint_allowlist", raw)
			if got := LoadAllowedEndpoints(v); len(got) != 0 {
				t.Errorf("LoadAllowedEndpoints()=%v, want 빈 목록", got)
			}
		})
	}
}

// TestLoadAllowedEndpoints_envOverride 는 공유 로더 구성(AutomaticEnv + 점->밑줄 replacer)에서
// STS_ENDPOINT_ALLOWLIST 환경변수가 config.yaml 파일값을 덮어쓰고, 콤마 목록을 트리밍해
// 반환하는지 확인한다. override 이름이 sts.endpoint_allowlist 키에 실제로 연결되는지 잠근다.
func TestLoadAllowedEndpoints_envOverride(t *testing.T) {
	v := configtest.Loader(t, "sts:\n  endpoint_allowlist: https://from-file.example\n")

	t.Setenv("STS_ENDPOINT_ALLOWLIST", " https://a.example, ,https://b.example ")

	got := LoadAllowedEndpoints(v)
	want := []string{"https://a.example", "https://b.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LoadAllowedEndpoints()=%v, want %v (STS_ENDPOINT_ALLOWLIST override 미반영)", got, want)
	}
}

// TestLoadCAFile 는 sts.ca_file 값을 앞뒤 공백을 다듬어 돌려주고, 미설정이면 빈 문자열을
// 돌려주는지 확인한다(조립 지점이 이때 CA 주입을 건너뛴다).
func TestLoadCAFile(t *testing.T) {
	t.Run("설정값 트리밍", func(t *testing.T) {
		v := viper.New()
		v.Set("sts.ca_file", "  ./mocksts-ca.pem  ")
		if got := LoadCAFile(v); got != "./mocksts-ca.pem" {
			t.Errorf("LoadCAFile()=%q, want %q", got, "./mocksts-ca.pem")
		}
	})
	t.Run("미설정은 빈 문자열", func(t *testing.T) {
		if got := LoadCAFile(viper.New()); got != "" {
			t.Errorf("LoadCAFile()=%q, want 빈 문자열", got)
		}
	})
	t.Run("env override", func(t *testing.T) {
		v := configtest.Loader(t, "sts:\n  ca_file: ./from-file.pem\n")
		t.Setenv("STS_CA_FILE", "./from-env.pem")
		if got := LoadCAFile(v); got != "./from-env.pem" {
			t.Errorf("LoadCAFile()=%q, want %q (STS_CA_FILE override 미반영)", got, "./from-env.pem")
		}
	})
}

// TestLoadCAPool_success 는 유효한 PEM CA 파일을 읽어 non-nil CertPool 을 돌려주는지 확인한다.
// democert 로 데모 인증서를 생성해 그 PEM 을 임시 파일에 써서 실제 로드 경로를 태운다.
func TestLoadCAPool_success(t *testing.T) {
	_, certPEM, err := democert.Generate([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("democert.Generate 실패: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("임시 CA 파일 쓰기 실패: %v", err)
	}

	pool, err := LoadCAPool(path)
	if err != nil {
		t.Fatalf("LoadCAPool()=%v, want nil error", err)
	}
	if pool == nil {
		t.Fatal("LoadCAPool()=nil pool, want non-nil")
	}
}

// TestLoadCAPool_errors 는 잘못된 경로/PEM 을 에러로 거부하는지 확인한다(오설정을 부팅
// 시점에 드러냄).
func TestLoadCAPool_errors(t *testing.T) {
	t.Run("존재하지 않는 경로", func(t *testing.T) {
		if _, err := LoadCAPool(filepath.Join(t.TempDir(), "없음.pem")); err == nil {
			t.Fatal("LoadCAPool()=nil error, want 읽기 실패 에러")
		}
	})
	t.Run("유효한 PEM 아님", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "garbage.pem")
		if err := os.WriteFile(path, []byte("이것은 PEM 이 아님"), 0o600); err != nil {
			t.Fatalf("임시 파일 쓰기 실패: %v", err)
		}
		if _, err := LoadCAPool(path); err == nil {
			t.Fatal("LoadCAPool()=nil error, want PEM 없음 에러")
		}
	})
}
