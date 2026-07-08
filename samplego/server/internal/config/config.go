// Package config 는 서버의 공유 설정 로더다. viper 로 저장소 루트의 config.yaml 을 읽어
// 하나의 *viper.Viper 로 돌려주고, 각 어댑터는 이 인스턴스에서 자기 섹션(예: jwt)을 꺼내
// 검증한다. 설정 소스를 한 곳(config.yaml + 환경변수 override)으로 모아, 어댑터마다 흩어진
// 환경변수 읽기를 대신한다.
//
// 자격 발급(jwt), 정책(policy), STS(sts) 어댑터가 모두 이 로더를 통해 각자의 섹션을 읽는다.
// 어댑터마다 흩어져 있던 환경변수 직접 읽기를 config.yaml 한 곳으로 모았다.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// configName 은 확장자를 뺀 설정 파일 이름이다(config.yaml).
const configName = "config"

// configType 은 설정 파일 형식이다.
const configType = "yaml"

// Load 는 현재 작업 디렉토리에서 config.yaml 을 찾아 읽은 viper 인스턴스를 돌려준다.
// 서버는 이 인스턴스를 조립 지점에서 각 어댑터의 Load 로 넘긴다. 파일이 없거나 파싱에
// 실패하면 에러를 반환해, 오설정을 부팅 시점에 드러낸다.
func Load() (*viper.Viper, error) {
	return load(".")
}

// load 는 주어진 디렉토리들에서 config.yaml 을 찾아 읽는다. Load 는 실행 위치(".")를,
// 테스트는 임시 디렉토리를 넘긴다.
//
// 환경변수 override 를 켜 둔다: 파일값 위에 환경변수가 우선한다. 키의 점(.)을 밑줄(_)로
// 바꿔 대조하므로, 예컨대 jwt.signing_secret 은 JWT_SIGNING_SECRET 으로 덮어쓸 수 있다.
// 커밋된 샘플 시크릿을 실제 배포에서 안전하게 대체하기 위한 통로다.
func load(paths ...string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName(configName)
	v.SetConfigType(configType)
	for _, p := range paths {
		v.AddConfigPath(p)
	}

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("설정 파일(%s.%s) 로드 실패: %w", configName, configType, err)
	}
	return v, nil
}
