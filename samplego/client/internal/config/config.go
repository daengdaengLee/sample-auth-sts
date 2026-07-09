// Package config 는 샘플 워크로드 클라이언트의 설정 로드(README "클라이언트 > 증명 생성 및
// 전송"의 1단계)를 맡는다. 서버가 헥사고날인 것과 달리 클라이언트는 절차 중심이라, 설정도
// 별도 어댑터 계층 없이 stdlib flag 와 환경변수만으로 단순하게 읽는다. AWS 자격증명은 여기서
// 다루지 않고 표준 AWS SDK 자격증명 체인에 위임한다(README 클라이언트 2단계).
package config

import (
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	// formHeader 는 헤더 기반 서명(X-Amz-Date 기준, 예: Vault)을 가리키는 증명 형태 값이다.
	// 현재 서버는 헤더에서 date/binding 을 추출하므로 이 형태만 지원한다.
	formHeader = "header"

	// formPresigned 는 pre-signed URL 형태(X-Amz-Expires 로 만료 직접 지정, 예: AWS IAM
	// Authenticator)를 가리킨다. 후속 작업이며, 현재는 명시적으로 거부한다.
	formPresigned = "presigned"
)

// Config 는 클라이언트가 증명을 만들어 보내는 데 필요한 설정 묶음이다. 기본값은 서버
// config.yaml 과 정렬해, 로컬 데모가 추가 설정 없이 바로 통과하도록 맞춘다.
type Config struct {
	// ServerAddr 는 서명된 요청을 보낼 대상 서버 주소다(README 설정의 "서버 주소").
	ServerAddr string

	// BindingValue 는 서명 범위에 넣는 서버 바인딩 헤더 값이다(혼동된 대리자 완화). 서버의
	// policy.binding_value 와 일치해야 한다(공통 설정).
	BindingValue string

	// STSEndpoint 는 SigV4 서명 대상이자 위임 대상 URL 이다. 서버의 sts.endpoint_allowlist
	// 안에 있어야 하며 https 여야 한다(공통 설정).
	STSEndpoint string

	// Region 은 SigV4 서명에 쓰는 AWS 리전이다. 엔드포인트와 일치해야 한다(global
	// sts.amazonaws.com 은 us-east-1).
	Region string

	// Form 은 증명 형태다(header/presigned). 현재는 header 만 유효하다.
	Form string

	// Verify 는 발급받은 토큰을 /verify 로 왕복 확인할지 여부다(데모 편의).
	Verify bool

	// StaticCreds 가 참이면 SDK 자격증명 체인 대신 아래 static 값으로 서명한다. 실 AWS
	// 자격증명 없이 목 STS 로 로컬 데모/오프라인 구동을 돌릴 때 쓴다.
	StaticCreds        bool
	StaticAccessKeyID  string
	StaticSecretKey    string
	StaticSessionToken string
}

// UsesPresigned 는 설정된 증명 형태가 pre-signed URL 인지 알려준다. 호출부가 후속 미지원을
// 안내하는 데 쓴다.
func (c Config) UsesPresigned() bool { return c.Form == formPresigned }

// Load 는 프로세스 인자와 환경변수에서 설정을 읽어 검증한다. os.Args[1:] 와 os.Getenv 를 쓰는
// 실행용 진입점이며, 테스트는 parse 로 인자/환경 조회를 주입한다.
func Load() (Config, error) {
	return parse("client", os.Args[1:], os.Getenv, os.Stderr)
}

// parse 는 주어진 인자 목록과 환경 조회 함수로 설정을 만든다. 각 플래그는 기본값으로 대응
// 환경변수를 먼저 반영하고, 명시된 플래그가 그 위에 우선한다(서버의 "파일값 위에 환경변수"와
// 반대 방향이지만, CLI 관례상 명시 인자가 가장 강함). 알 수 없는 형태는 여기서 거부한다.
func parse(name string, args []string, getenv func(string) string, errOut io.Writer) (Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)

	// 기본값은 대응 환경변수가 있으면 그 값, 없으면 서버 config.yaml 과 정렬한 리터럴이다.
	serverAddr := fs.String("server-addr", envOr(getenv, "SERVER_ADDR", "http://localhost:8080"), "요청을 보낼 대상 서버 주소")
	bindingValue := fs.String("binding-value", envOr(getenv, "CLIENT_BINDING_VALUE", "https://server.example/audience"), "서명 범위에 넣을 서버 바인딩 헤더 값")
	stsEndpoint := fs.String("sts-endpoint", envOr(getenv, "STS_ENDPOINT", "https://sts.amazonaws.com"), "SigV4 서명/위임 대상 STS 엔드포인트(https)")
	region := fs.String("region", envOr(getenv, "AWS_REGION", "us-east-1"), "SigV4 서명 리전")
	form := fs.String("form", envOr(getenv, "CLIENT_PROOF_FORM", formHeader), "증명 형태(header 만 지원, presigned 는 후속)")
	verify := fs.Bool("verify", envBool(getenv, "CLIENT_VERIFY"), "발급 토큰을 /verify 로 왕복 확인")

	staticCreds := fs.Bool("static-creds", envBool(getenv, "CLIENT_STATIC_CREDS"), "SDK 체인 대신 static 자격증명으로 서명(목 STS 데모용)")
	staticAccessKeyID := fs.String("static-access-key-id", envOr(getenv, "CLIENT_STATIC_ACCESS_KEY_ID", ""), "static 자격증명 액세스 키 ID")
	staticSecretKey := fs.String("static-secret-key", envOr(getenv, "CLIENT_STATIC_SECRET_KEY", ""), "static 자격증명 시크릿 키")
	staticSessionToken := fs.String("static-session-token", envOr(getenv, "CLIENT_STATIC_SESSION_TOKEN", ""), "static 자격증명 세션 토큰(임시 자격증명)")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg := Config{
		ServerAddr:         *serverAddr,
		BindingValue:       *bindingValue,
		STSEndpoint:        *stsEndpoint,
		Region:             *region,
		Form:               *form,
		Verify:             *verify,
		StaticCreds:        *staticCreds,
		StaticAccessKeyID:  *staticAccessKeyID,
		StaticSecretKey:    *staticSecretKey,
		StaticSessionToken: *staticSessionToken,
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate 는 필수값과 형태 제약을 확인한다. 빈 값은 데모를 조용히 실패시키므로 로드 시점에
// 드러내고, 미지원 형태(presigned)는 여기서 명확히 거른다(후속 작업 안내).
func (c Config) validate() error {
	if c.ServerAddr == "" {
		return fmt.Errorf("server-addr 가 비어 있음")
	}
	if c.BindingValue == "" {
		return fmt.Errorf("binding-value 가 비어 있음(서버 policy.binding_value 와 일치해야 함)")
	}
	if c.STSEndpoint == "" {
		return fmt.Errorf("sts-endpoint 가 비어 있음")
	}
	if c.Region == "" {
		return fmt.Errorf("region 이 비어 있음")
	}
	switch c.Form {
	case formHeader:
		// 현재 서버가 지원하는 유일한 형태다.
	case formPresigned:
		return fmt.Errorf("form=presigned 는 아직 미지원(후속): 현재 서버는 헤더 기반만 받는다")
	default:
		return fmt.Errorf("form 값이 올바르지 않음(%q): header 만 지원", c.Form)
	}
	if c.StaticCreds && (c.StaticAccessKeyID == "" || c.StaticSecretKey == "") {
		return fmt.Errorf("static-creds 사용 시 static-access-key-id 와 static-secret-key 가 필요함")
	}
	return nil
}

// envOr 는 환경변수 key 가 비어 있지 않으면 그 값을, 아니면 fallback 을 돌려준다. 플래그
// 기본값에 환경변수를 반영하는 데 쓴다.
func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

// envBool 은 불리언 환경변수를 해석한다. "1"/"true"(대소문자 무시)만 참으로 보고 나머지는
// 거짓으로 둔다. 플래그가 명시되면 그 값이 우선한다.
func envBool(getenv func(string) string, key string) bool {
	switch v := getenv(key); v {
	case "1", "true", "TRUE", "True":
		return true
	default:
		return false
	}
}
