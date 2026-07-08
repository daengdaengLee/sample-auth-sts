// Package configtest 는 설정 어댑터 테스트용 헬퍼다. 공유 로더(internal/config)와 동일한 env
// 해석 구성을 가진 viper 를 yaml 문자열로 만들어, 어댑터가 환경변수 override 를 실제 로더와
// 같은 방식으로 해석하는지 검증하게 한다. viper.Set 은 최우선 override 를 직접 주입해 env 해석
// 경로를 우회하므로, env override 회귀 테스트에는 이 헬퍼를 쓴다.
package configtest

import (
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/config"
)

// Loader 는 yaml 문자열을 파일값으로 읽고, 공유 로더와 동일한 env override 배선을 켠 viper 를
// 돌려준다. env 배선은 config.EnableEnvOverride 한 곳에서만 정의되므로 로더가 바뀌면 이 헬퍼도
// 함께 바뀐다(테스트가 실제 로더와 어긋나는 드리프트 방지).
func Loader(t *testing.T, yamlBody string) *viper.Viper {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(yamlBody)); err != nil {
		t.Fatalf("설정 파싱 실패: %v", err)
	}
	config.EnableEnvOverride(v)
	return v
}
