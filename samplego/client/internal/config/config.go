// Package config 는 샘플 워크로드 클라이언트의 설정 로드(README "클라이언트 > 증명 생성 및
// 전송"의 1단계)를 맡는다. 서버가 헥사고날인 것과 달리 클라이언트는 절차 중심이라, 설정도
// 별도 어댑터 계층 없이 stdlib flag 와 환경변수만으로 단순하게 읽는다. AWS 자격증명은 여기서
// 다루지 않고 표준 AWS SDK 자격증명 체인에 위임한다(README 클라이언트 2단계).
package config

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// awsRegionRe 는 AWS 리전 식별자의 형식이다. 표준(us-east-1), gov(us-gov-west-1),
// cn(cn-north-1) 형태를 모두 포용한다. 리전 유효성 자체(실재 여부)는 형식만으로 판별할 수
// 없으므로(그럴듯한 오타는 형식상 정상), 이 검사는 리전답지 않은 문자열만 거른다.
var awsRegionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

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

	// Timeout 은 실행 전체(자격증명 획득 + 서버 /auth, /verify 요청)의 최대 소요 시간이다.
	// 무응답 서버/STS 지연이나 느린 자격증명 획득에 무한정 매달리지 않도록, 실행 파이프라인을
	// 감싸는 컨텍스트 데드라인이자 요청별 http.Client 타임아웃으로 쓴다.
	Timeout time.Duration

	// StaticCreds 가 참이면 SDK 자격증명 체인 대신 아래 static 값으로 서명한다. 실 AWS
	// 자격증명 없이 목 STS 로 로컬 데모/오프라인 구동을 돌릴 때 쓴다.
	StaticCreds        bool
	StaticAccessKeyID  string
	StaticSecretKey    string
	StaticSessionToken string
}

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
	timeoutRaw := fs.String("timeout", envOr(getenv, "CLIENT_TIMEOUT", "30s"), "실행 전체(자격증명 획득 + 서버 요청)의 최대 소요 시간(time.ParseDuration 형식)")

	staticCreds := fs.Bool("static-creds", envBool(getenv, "CLIENT_STATIC_CREDS"), "SDK 체인 대신 static 자격증명으로 서명(목 STS 데모용)")
	staticAccessKeyID := fs.String("static-access-key-id", envOr(getenv, "CLIENT_STATIC_ACCESS_KEY_ID", ""), "static 자격증명 액세스 키 ID")
	staticSecretKey := fs.String("static-secret-key", envOr(getenv, "CLIENT_STATIC_SECRET_KEY", ""), "static 자격증명 시크릿 키")
	staticSessionToken := fs.String("static-session-token", envOr(getenv, "CLIENT_STATIC_SESSION_TOKEN", ""), "static 자격증명 세션 토큰(임시 자격증명)")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	// 타임아웃은 서버 어댑터의 duration 파싱과 같은 톤으로 time.ParseDuration 으로 해석하고,
	// 형식 오류는 로드 시점에 드러낸다(양수 검증은 validate 가 맡는다).
	timeout, err := time.ParseDuration(*timeoutRaw)
	if err != nil {
		return Config{}, fmt.Errorf("timeout 파싱 실패(%q): %w", *timeoutRaw, err)
	}

	// region 과 sts-endpoint 는 반드시 일치해야 하는데 기본값이 독립 소스(AWS_REGION 대 global)라
	// 기본끼리 충돌할 수 있다. 두 손잡이의 "명시 강도"를 비교해, 더 강하게 명시된 쪽에서 약한
	// 쪽을 파생해 충돌을 없앤다. 강도가 같으면(둘 다 플래그/둘 다 env/둘 다 기본) 그대로 두고
	// validate 가 정합성을 검사한다.
	//
	// 강도: 0=기본, 1=환경변수(ambient), 2=플래그(이번 실행의 명시 의도). 플래그가 env 를, env 가
	// 기본을 이긴다. 두 축을 대칭으로 다루므로, 엔드포인트 플래그가 ambient AWS_REGION 을 이기는
	// 것과 리전 플래그가 ambient STS_ENDPOINT 를 이기는 것이 똑같이 성립한다.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	strengthOf := func(flagName, envKey string) int {
		s := 0
		if getenv(envKey) != "" {
			s = 1
		}
		if set[flagName] {
			s = 2
		}
		return s
	}
	regionStrength := strengthOf("region", "AWS_REGION")
	endpointStrength := strengthOf("sts-endpoint", "STS_ENDPOINT")

	regionVal, endpointVal := *region, *stsEndpoint
	deriveRegionFromEndpoint := func() {
		// 표준 STS 호스트면 리전을 엔드포인트에서 파생한다(그 외면 그대로 두고 validate 가 검사).
		if u, perr := url.Parse(endpointVal); perr == nil {
			if r, ok := regionForSTSHost(u.Hostname()); ok {
				regionVal = r
			}
		}
	}
	deriveEndpointFromRegion := func() {
		// 표준 파티션이면 엔드포인트를 리전에서 파생한다. 파생할 수 없으면(cn 등) 기본 global 을
		// 유지해, validate 가 불일치를 명확히 안내하게 한다.
		if ep, ok := endpointForRegion(regionVal); ok {
			endpointVal = ep
		}
	}
	switch {
	case regionStrength > endpointStrength:
		// 리전이 더 강하게 명시됨: 엔드포인트를 리전에서 파생한다.
		deriveEndpointFromRegion()
	case endpointStrength > regionStrength:
		// 엔드포인트가 더 강하게 명시됨: 리전을 엔드포인트에서 파생한다.
		deriveRegionFromEndpoint()
	}

	cfg := Config{
		ServerAddr:         *serverAddr,
		BindingValue:       *bindingValue,
		STSEndpoint:        endpointVal,
		Region:             regionVal,
		Form:               *form,
		Verify:             *verify,
		Timeout:            timeout,
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
	// STS 엔드포인트는 비어 있지 않을 뿐 아니라 https 여야 한다. 서버 STS 어댑터의
	// normalizeEndpoint 가 비-https 를 거부하므로(평문 다운그레이드 차단), http 값을 로컬에서
	// 통과시키면 서버가 불투명한 401 로 떨구게 된다. 여기서 명확한 로컬 에러로 미리 거른다.
	stsURL, err := url.Parse(c.STSEndpoint)
	if err != nil {
		return fmt.Errorf("sts-endpoint 파싱 실패(%q): %w", c.STSEndpoint, err)
	}
	if stsURL.Scheme != "https" || stsURL.Host == "" {
		return fmt.Errorf("sts-endpoint 는 https URL 이어야 함(현재 %q): 서버가 비-https 위임 대상을 거부한다", c.STSEndpoint)
	}
	if c.Region == "" {
		return fmt.Errorf("region 이 비어 있음")
	}
	// 리전 형식 검사: 리전답지 않은 문자열(garbage, eu_west_1 등)을 로컬에서 명확히 거른다.
	// 형식상 정상인 오타(eu-wast-1 등)는 여기서 못 거르며(형식만으로 실재 여부는 판별 불가),
	// 서버의 STS 허용 목록/검증으로 넘어간다.
	if !awsRegionRe.MatchString(c.Region) {
		return fmt.Errorf("region 형식이 올바르지 않음(%q): AWS 리전 형식이어야 함(예: us-east-1)", c.Region)
	}
	// 표준 STS 호스트에서 리전을 파생할 수 있으면 서명 리전과 대조한다. 한쪽만 기본에서 바꾼
	// 절반-수정(예: 리전형 엔드포인트 + 기본 us-east-1)은 실 STS 가 서명을 거절해 불투명한 401
	// 로 이어지므로, 여기서 명확한 로컬 에러로 미리 거른다. 표준 호스트가 아니면(커스텀/사설/타
	// 파티션) 파생을 못 하므로 검사를 건너뛴다(과잉 거부 방지).
	if r, ok := regionForSTSHost(stsURL.Hostname()); ok && r != c.Region {
		return fmt.Errorf("region(%q) 과 sts-endpoint 리전(%q)이 불일치: 서명 리전과 엔드포인트가 맞아야 STS 가 서명을 검증한다", c.Region, r)
	}
	switch c.Form {
	case formHeader:
		// 현재 서버가 지원하는 유일한 형태다.
	case formPresigned:
		return fmt.Errorf("form=presigned 는 아직 미지원(후속): 현재 서버는 헤더 기반만 받는다")
	default:
		return fmt.Errorf("form 값이 올바르지 않음(%q): header 만 지원", c.Form)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout 은 양수여야 함(현재 %v): 0 이하면 요청 경계가 없어진다", c.Timeout)
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

// envBool 은 불리언 환경변수를 해석한다. strconv.ParseBool 이 받아들이는 값("1","t","T",
// "TRUE","true","True" 등)을 참으로 본다. 미설정/빈 값/해석 불가는 거짓으로 둔다. 플래그가
// 명시되면 그 값이 우선한다.
func envBool(getenv func(string) string, key string) bool {
	b, err := strconv.ParseBool(getenv(key))
	if err != nil {
		return false
	}
	return b
}

// regionForSTSHost 는 표준 AWS STS 호스트에서 SigV4 서명 리전을 파생한다. 판정 가능한 표준
// 형태만 다루고(known=true), 그 외(커스텀/사설) 호스트는 known=false 로 돌려 정합성 검사를
// 건너뛰게 한다(과잉 거부 방지). 파생이 아니라 인식/대조이므로 파티션을 넓게 다뤄도 위험이 없다.
// 표준 형태:
//   - sts.amazonaws.com (global): us-east-1 로 서명해야 유효하다.
//   - sts[.-fips].<region>.amazonaws.com (표준/gov): <region>.
//   - sts[.-fips].<region>.amazonaws.com.cn (중국): <region>.
//   - sts.<region>.api.aws (dualstack): <region>.
//
// 표준 파티션 패턴만 유지하는 손수 목록이라, 미열거 형태(예: FIPS dualstack, 신규 파티션
// 접미사)는 known=false 로 스킵돼 정합성 검사를 못 받는다. 그런 대상은 --sts-endpoint 와
// --region 을 함께 명시해야 한다(AWS SDK 엔드포인트 리졸버 채택은 수동 SigV4 라 범위 밖).
func regionForSTSHost(host string) (string, bool) {
	host = strings.ToLower(host)
	if host == "sts.amazonaws.com" {
		return "us-east-1", true
	}
	parts := strings.Split(host, ".")
	stsLabel := len(parts) > 0 && (parts[0] == "sts" || parts[0] == "sts-fips")
	switch {
	case len(parts) == 4 && stsLabel && parts[2] == "amazonaws" && parts[3] == "com":
		// 표준/gov: sts.<region>.amazonaws.com
		return parts[1], true
	case len(parts) == 5 && stsLabel && parts[2] == "amazonaws" && parts[3] == "com" && parts[4] == "cn":
		// 중국: sts.<region>.amazonaws.com.cn
		return parts[1], true
	case len(parts) == 4 && parts[0] == "sts" && parts[2] == "api" && parts[3] == "aws":
		// dualstack: sts.<region>.api.aws
		return parts[1], true
	}
	return "", false
}

// endpointForRegion 은 서명 리전에서 표준 STS 엔드포인트 URL 을 파생한다. 잘못된 호스트를
// 만들지 않는 것이 원칙이라, 확실히 조립할 수 있는 표준/gov 파티션만 다루고(ok=true) 그 외
// (중국 등 호스트 문법이 다른 파티션)는 ok=false 로 돌려 호출부가 명시를 요구하게 한다.
//   - us-east-1: global sts.amazonaws.com (서버 기본 allowlist 와 정렬).
//   - 그 외 표준/gov 리전: sts.<region>.amazonaws.com.
func endpointForRegion(region string) (string, bool) {
	if region == "us-east-1" {
		return "https://sts.amazonaws.com", true
	}
	if strings.HasPrefix(region, "cn-") {
		return "", false // 중국 파티션은 .amazonaws.com.cn 이라 파생하지 않는다(명시 필요).
	}
	return "https://sts." + region + ".amazonaws.com", true
}
