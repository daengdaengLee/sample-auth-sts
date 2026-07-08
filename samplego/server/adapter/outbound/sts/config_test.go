package sts

import (
	"reflect"
	"testing"

	"github.com/spf13/viper"
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
