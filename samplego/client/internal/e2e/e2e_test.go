//go:build e2e

// Package e2e 는 클라이언트가 실제 서버 라우터를 상대로 서명 -> 전송 -> 발급 -> 검증 왕복을
// end-to-end 로 구동하는 크로스모듈 테스트다. 서버 모듈을 replace 로 끌어와 실제
// inbound.NewRouter 와 실제 아웃바운드 어댑터를 조립하고, 목 STS(httptest TLS)로 위임을
// 흉내낸다. 서버 acceptance 코드를 그대로 태우므로, 클라이언트가 만든 엔벨로프가 서버 와이어
// 계약과 실제로 맞물리는지 검증한다(서버 검증 로직을 복제하지 않아 drift 가 없다).
//
// 기본 go test 를 가볍게 유지하려고 e2e 빌드 태그로 격리한다. 실행: go test -tags e2e ./...
// 목 STS 는 서명을 검증하지 않으므로 실 AWS 자격증명이 필요 없다(static dummy 로 서명).
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/viper"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/inbound"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/clock"
	policycfg "github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/config"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/issuer"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/sts"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"

	clientconfig "github.com/daengdaenglee/sample-auth-sts/samplego/client/internal/config"
	"github.com/daengdaenglee/sample-auth-sts/samplego/client/internal/proof"
	"github.com/daengdaenglee/sample-auth-sts/samplego/client/internal/transport"
)

const (
	testBinding = "https://server.example/audience"
	testARN     = "arn:aws:iam::123456789012:role/workload"
	testSecret  = "sample-only-hs256-secret-change-me-in-real-deployments"
	testIssuer  = "https://server.example"
	testAud     = "https://server.example/clients"
)

// TestPresignExpiryBoundsAgree 는 클라이언트와 서버의 presigned 만료 상한이 같은 값인지 확인한다.
// 두 상수는 별도 모듈이라 공유할 수 없어 각자 중복 정의되는데, 어긋나면 클라이언트가 로컬에서
// 통과시킨 만료를 서버가 거부하는(로컬 수락 -> 원격 거부) 안티패턴이 재발한다. 크로스모듈 계약을
// 검증하는 이 e2e 테스트가 초 환산 동일성을 단언해 그 divergence 를 부팅 없이 회귀로 잡는다.
func TestPresignExpiryBoundsAgree(t *testing.T) {
	clientSecs := int64(clientconfig.MaxPresignExpiry / time.Second)
	if clientSecs != int64(inbound.MaxPresignExpirySeconds) {
		t.Fatalf("presigned 만료 상한 불일치: 클라이언트 %ds, 서버 %ds (두 상수를 같은 값으로 맞춰야 함)", clientSecs, inbound.MaxPresignExpirySeconds)
	}
}

// stsResponseXML 은 목 STS 가 돌려줄 GetCallerIdentity 성공 응답이다. ARN 은 서버 허용 목록과
// 일치시킨다.
const stsResponseXML = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:role/workload</Arn>
    <UserId>AIDAEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`

// buildServerConfig 는 서버 어댑터들이 읽을 viper 를 직접 구성한다. 서버 internal 로더는
// 다른 모듈에서 import 할 수 없으므로, 어댑터가 읽는 키만 v.Set 으로 채운다(GetString 이 그대로
// 읽는다). STS 허용 목록은 목 STS URL 로 둔다.
func buildServerConfig(stsURL string) *viper.Viper {
	v := viper.New()
	v.Set("policy.binding_value", testBinding)
	v.Set("policy.request_max_age", "5m")
	v.Set("policy.allowed_arns", testARN)
	v.Set("jwt.signing_secret", testSecret)
	v.Set("jwt.ttl", "15m")
	v.Set("jwt.issuer", testIssuer)
	v.Set("jwt.audience", testAud)
	v.Set("sts.endpoint_allowlist", stsURL)
	return v
}

// assembleRouter 는 main.buildServices 와 같은 배선을 테스트에서 재현한다(그 함수는 package
// main 이라 import 불가). 실제 아웃바운드 어댑터와 도메인 서비스를 조립해 실제 라우터를 만든다.
// STS 검증기는 목 STS 의 TLS 를 신뢰하도록 목 서버 client 를 쓴다.
func assembleRouter(t *testing.T, v *viper.Viper, stsClient *http.Client) http.Handler {
	t.Helper()

	policy, err := policycfg.Load(v)
	if err != nil {
		t.Fatalf("정책 로드 실패: %v", err)
	}
	issuerParams, err := issuer.Load(v)
	if err != nil {
		t.Fatalf("발급 설정 로드 실패: %v", err)
	}

	clk := clock.New()
	verifier := sts.New(stsClient, sts.LoadAllowedEndpoints(v))
	iss := issuer.New(issuerParams)
	authService := domain.NewService(policy, clk, verifier, iss)

	inspector := issuer.NewInspector(issuerParams)
	verifyPolicy := issuer.NewVerifyPolicy(issuerParams)
	tokenVerifier := domain.NewVerifyService(clk, inspector, verifyPolicy)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return inbound.NewRouter(logger, authService, tokenVerifier)
}

// TestClientEndToEnd 는 클라이언트가 실제 서버를 상대로 인증 왕복을 완주하는지 확인한다:
// 목 STS 세움 -> 실 라우터 조립 -> 클라이언트 서명 -> /auth 로 200 + JWT 수령 -> /verify 로
// 클레임 왕복 확인.
func TestClientEndToEnd(t *testing.T) {
	// 목 STS: https 만 허용되므로 TLS 서버여야 한다. 서명은 검증하지 않고 캡처만 한다.
	type captured struct {
		method  string
		body    string
		binding string
	}
	gotSTS := make(chan captured, 1)
	stsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotSTS <- captured{method: r.Method, body: string(b), binding: r.Header.Get("X-Server-Binding")}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, stsResponseXML)
	}))
	defer stsSrv.Close()

	// 실제 서버 라우터를 조립해 httptest 로 서빙한다(평문 HTTP; 클라이언트 -> 서버 데모 경로).
	v := buildServerConfig(stsSrv.URL)
	router := assembleRouter(t, v, stsSrv.Client())
	appSrv := httptest.NewServer(router)
	defer appSrv.Close()

	// 클라이언트: static dummy 자격증명으로 목 STS 를 대상으로 서명한다(실 AWS 불필요).
	env, err := proof.BuildProof(context.Background(), proof.Input{
		Credentials:  aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secretexamplekey"},
		Endpoint:     stsSrv.URL,
		Region:       "us-east-1",
		BindingValue: testBinding,
		SignedAt:     time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildProof 실패: %v", err)
	}

	client := transport.New(appSrv.URL, nil)

	// /auth: 200 과 발급 JWT 를 받는다.
	authResult, err := client.PostAuth(context.Background(), env)
	if err != nil {
		t.Fatalf("PostAuth 실패: %v", err)
	}
	if authResult.Token == "" {
		t.Fatal("발급 토큰이 비어 있음")
	}
	if parts := strings.Split(authResult.Token, "."); len(parts) != 3 {
		t.Fatalf("발급 토큰이 JWT(3 세그먼트) 형태가 아님: %q", authResult.Token)
	}

	// 위임이 실제로 일어났고 원본이 충실히 전달됐는지 확인한다.
	select {
	case c := <-gotSTS:
		if c.method != http.MethodPost {
			t.Errorf("STS 로 위임된 메서드 = %q, want POST", c.method)
		}
		if c.body != "Action=GetCallerIdentity&Version=2011-06-15" {
			t.Errorf("STS 로 위임된 바디 = %q", c.body)
		}
		if c.binding != testBinding {
			t.Errorf("STS 로 위임된 X-Server-Binding = %q", c.binding)
		}
	default:
		t.Error("목 STS 가 요청을 받지 못함(위임이 일어나지 않음)")
	}

	// 발급 토큰의 페이로드 클레임이 서버 설정에서 온 값인지 직접 확인한다.
	assertClaim(t, authResult.Token, testIssuer, testARN, testAud)

	// /verify: 발급 토큰을 왕복해 클레임을 되받는다(데모의 마지막 절반).
	claims, err := client.PostVerify(context.Background(), authResult.Token)
	if err != nil {
		t.Fatalf("PostVerify 실패: %v", err)
	}
	if claims.Issuer != testIssuer {
		t.Errorf("verify iss = %q, want %q", claims.Issuer, testIssuer)
	}
	if claims.Subject != testARN {
		t.Errorf("verify sub = %q, want %q", claims.Subject, testARN)
	}
	if claims.Audience != testAud {
		t.Errorf("verify aud = %q, want %q", claims.Audience, testAud)
	}
	if claims.Account != "123456789012" {
		t.Errorf("verify account = %q, want 123456789012", claims.Account)
	}
}

// TestClientEndToEnd_presigned 는 presigned 형태(GET 쿼리 서명)로도 인증 왕복을 완주하는지
// 확인한다. 클라이언트가 BuildPresignedProof 로 서명하고, 실 라우터가 쿼리 기반 형태를 추출/검증해
// 자격을 발급하며, 목 STS 가 GET 위임과 서명 범위의 바인딩 헤더를 받는지 본다(헤더 기반과 공존).
func TestClientEndToEnd_presigned(t *testing.T) {
	type captured struct {
		method  string
		binding string
	}
	gotSTS := make(chan captured, 1)
	stsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSTS <- captured{method: r.Method, binding: r.Header.Get("X-Server-Binding")}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, stsResponseXML)
	}))
	defer stsSrv.Close()

	v := buildServerConfig(stsSrv.URL)
	router := assembleRouter(t, v, stsSrv.Client())
	appSrv := httptest.NewServer(router)
	defer appSrv.Close()

	// 클라이언트: presigned 형태로 서명한다(만료를 서버 max-age(5m)보다 짧게 잡아 창을 좁힌다).
	env, err := proof.BuildPresignedProof(context.Background(), proof.Input{
		Credentials:  aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secretexamplekey"},
		Endpoint:     stsSrv.URL,
		Region:       "us-east-1",
		BindingValue: testBinding,
		SignedAt:     time.Now(),
		Expiry:       2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("BuildPresignedProof 실패: %v", err)
	}
	if env.Method != http.MethodGet {
		t.Fatalf("presigned 엔벨로프 메서드 = %q, want GET", env.Method)
	}

	client := transport.New(appSrv.URL, nil)

	// /auth: 200 과 발급 JWT 를 받는다.
	authResult, err := client.PostAuth(context.Background(), env)
	if err != nil {
		t.Fatalf("PostAuth 실패: %v", err)
	}
	if parts := strings.Split(authResult.Token, "."); len(parts) != 3 {
		t.Fatalf("발급 토큰이 JWT(3 세그먼트) 형태가 아님: %q", authResult.Token)
	}

	// 위임이 GET 으로 일어났고 바인딩 헤더가 그대로 전달됐는지 확인한다.
	select {
	case c := <-gotSTS:
		if c.method != http.MethodGet {
			t.Errorf("STS 로 위임된 메서드 = %q, want GET", c.method)
		}
		if c.binding != testBinding {
			t.Errorf("STS 로 위임된 X-Server-Binding = %q", c.binding)
		}
	default:
		t.Error("목 STS 가 요청을 받지 못함(위임이 일어나지 않음)")
	}

	// 발급 토큰의 클레임이 서버 설정에서 온 값인지 확인하고, /verify 로 왕복한다.
	assertClaim(t, authResult.Token, testIssuer, testARN, testAud)
	claims, err := client.PostVerify(context.Background(), authResult.Token)
	if err != nil {
		t.Fatalf("PostVerify 실패: %v", err)
	}
	if claims.Subject != testARN {
		t.Errorf("verify sub = %q, want %q", claims.Subject, testARN)
	}
}

// assertClaim 은 JWT payload 세그먼트를 디코드해 iss/sub/aud 를 확인한다.
func assertClaim(t *testing.T, token, wantIss, wantSub, wantAud string) {
	t.Helper()
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("JWT payload base64url 디코드 실패: %v", err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("JWT 클레임 파싱 실패: %v", err)
	}
	if claims.Iss != wantIss {
		t.Errorf("iss = %q, want %q", claims.Iss, wantIss)
	}
	if claims.Sub != wantSub {
		t.Errorf("sub = %q, want %q", claims.Sub, wantSub)
	}
	if claims.Aud != wantAud {
		t.Errorf("aud = %q, want %q", claims.Aud, wantAud)
	}
}
