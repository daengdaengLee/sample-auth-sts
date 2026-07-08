package sts

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// loaderViper 는 공유 설정 로더(internal/config)와 동일하게 구성한 viper 를 만든다:
// yaml 파일값을 읽고 AutomaticEnv + 점->밑줄 replacer 를 켠다. viper.Set 은 env 해석 경로를
// 우회하므로, env override 회귀 테스트에는 실제 로더 구성을 재현한 이 헬퍼를 쓴다.
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
	v := loaderViper(t, "sts:\n  endpoint_allowlist: https://from-file.example\n")

	t.Setenv("STS_ENDPOINT_ALLOWLIST", " https://a.example, ,https://b.example ")

	got := LoadAllowedEndpoints(v)
	want := []string{"https://a.example", "https://b.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LoadAllowedEndpoints()=%v, want %v (STS_ENDPOINT_ALLOWLIST override 미반영)", got, want)
	}
}
