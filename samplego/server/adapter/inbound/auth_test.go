package inbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/clock"
	policyconfig "github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/config"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/issuer"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/sts"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/logging"
)

// fakeAuthenticator 는 인바운드 포트 대역이다. 주입한 결과/에러를 돌려주고, 호출 여부와
// 넘어온 입력을 기록해 HTTP 매핑과 파싱 결과를 격리 검증한다.
type fakeAuthenticator struct {
	out    domain.AuthenticateOutput
	err    error
	called bool
	gotIn  domain.AuthenticateInput
}

func (f *fakeAuthenticator) Authenticate(_ context.Context, in domain.AuthenticateInput) (domain.AuthenticateOutput, error) {
	f.called = true
	f.gotIn = in
	return f.out, f.err
}

// newAuthEngine 은 대역 포트를 주입한 라우터를 만든다. 로그는 버린다.
func newAuthEngine(auth domain.Authenticator) *gin.Engine {
	return NewRouter(logging.New(io.Discard, slog.LevelInfo), auth)
}

// doAuth 는 주어진 JSON 본문으로 /auth 를 호출한 결과를 돌려준다.
func doAuth(engine *gin.Engine, jsonBody []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// mustJSON 은 값을 JSON 으로 마샬한다.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("JSON 마샬 실패: %v", err)
	}
	return b
}

// validEnvelope 는 모든 사전검증을 통과하는 기준 엔벨로프를 만든다. 각 테스트는 필요한 필드만
// 바꿔 특정 검증 실패를 재현한다. Authorization 의 SignedHeaders 에 x-amz-date 와
// x-server-binding 을 모두 포함해 서명 범위 검증을 통과시킨다.
func validEnvelope() authRequest {
	return authRequest{
		Method: "POST",
		URL:    "https://sts.amazonaws.com/",
		Headers: map[string][]string{
			"Authorization":    {"AWS4-HMAC-SHA256 Credential=AKID/20260708/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date;x-server-binding, Signature=abcd"},
			"X-Amz-Date":       {"20260708T120000Z"},
			"Host":             {"sts.amazonaws.com"},
			"X-Server-Binding": {"https://server.example/audience"},
			"Content-Type":     {"application/x-www-form-urlencoded"},
		},
		Body: base64.StdEncoding.EncodeToString([]byte("Action=GetCallerIdentity&Version=2011-06-15")),
	}
}

// TestAuthenticate_success 는 성공 시 200 과 발급 자격이 응답되고, 엔벨로프에서 SignedRequest
// 필드가 올바로 유도돼 코어로 넘어가는지 확인한다.
func TestAuthenticate_success(t *testing.T) {
	exp := time.Date(2026, 7, 8, 12, 15, 0, 0, time.UTC)
	fake := &fakeAuthenticator{out: domain.AuthenticateOutput{
		Credential: domain.Credential{Token: "issued.jwt.token", ExpiresAt: exp},
		Identity:   domain.Identity{ARN: "arn:aws:iam::123456789012:role/workload"},
	}}

	rec := doAuth(newAuthEngine(fake), mustJSON(t, validEnvelope()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("응답 파싱 실패: %v", err)
	}
	if resp.Token != "issued.jwt.token" {
		t.Errorf("token = %q, want issued.jwt.token", resp.Token)
	}
	if resp.ExpiresAt != exp.Format(time.RFC3339) {
		t.Errorf("expires_at = %q, want %q", resp.ExpiresAt, exp.Format(time.RFC3339))
	}

	if !fake.called {
		t.Fatal("인바운드 포트가 호출되지 않음")
	}
	sr := fake.gotIn.Request
	if sr.BindingValue != "https://server.example/audience" {
		t.Errorf("BindingValue = %q", sr.BindingValue)
	}
	if sr.Method != "POST" {
		t.Errorf("Method = %q", sr.Method)
	}
	if sr.Action != "GetCallerIdentity" {
		t.Errorf("Action = %q", sr.Action)
	}
	wantAt := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	if !sr.SignedAt.Equal(wantAt) {
		t.Errorf("SignedAt = %v, want %v", sr.SignedAt, wantAt)
	}
	if sr.Original.URL != "https://sts.amazonaws.com/" {
		t.Errorf("Original.URL = %q", sr.Original.URL)
	}
	if got := string(sr.Original.Body); got != "Action=GetCallerIdentity&Version=2011-06-15" {
		t.Errorf("Original.Body = %q", got)
	}
}

// TestAuthenticate_invalidJSON 은 본문이 JSON 이 아니면 400 이고 코어를 호출하지 않는지 본다.
func TestAuthenticate_invalidJSON(t *testing.T) {
	fake := &fakeAuthenticator{}
	rec := doAuth(newAuthEngine(fake), []byte("{not json"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if fake.called {
		t.Error("파싱 실패인데 코어가 호출됨")
	}
}

// TestAuthenticate_preValidation 은 도메인 호출 전 사전검증 실패가 올바른 상태로 매핑되고,
// 코어를 호출하지 않는지 표로 확인한다.
func TestAuthenticate_preValidation(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(e *authRequest)
		wantStatus int
	}{
		{
			name:       "body base64 불량",
			mutate:     func(e *authRequest) { e.Body = "@@not-base64@@" },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "Authorization 부재",
			mutate:     func(e *authRequest) { delete(e.Headers, "Authorization") },
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "x-amz-date 미서명",
			mutate: func(e *authRequest) {
				e.Headers["Authorization"] = []string{"AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-server-binding, Signature=y"}
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "x-amz-date 헤더 부재",
			mutate:     func(e *authRequest) { delete(e.Headers, "X-Amz-Date") },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "x-amz-date 형식 불량",
			mutate:     func(e *authRequest) { e.Headers["X-Amz-Date"] = []string{"not-a-date"} },
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "x-server-binding 미서명",
			mutate: func(e *authRequest) {
				e.Headers["Authorization"] = []string{"AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-date, Signature=y"}
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "x-server-binding 헤더 부재",
			mutate:     func(e *authRequest) { delete(e.Headers, "X-Server-Binding") },
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAuthenticator{}
			env := validEnvelope()
			tc.mutate(&env)

			rec := doAuth(newAuthEngine(fake), mustJSON(t, env))

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if fake.called {
				t.Error("사전검증 실패인데 코어가 호출됨")
			}
		})
	}
}

// TestAuthenticate_errorMapping 은 코어/어댑터가 돌려준 에러가 올바른 HTTP 상태로 매핑되는지
// 표로 확인한다.
func TestAuthenticate_errorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"binding_mismatch", &domain.RejectionError{Reason: domain.ReasonBindingMismatch, Message: "x"}, http.StatusForbidden},
		{"invalid_shape", &domain.RejectionError{Reason: domain.ReasonInvalidShape, Message: "x"}, http.StatusBadRequest},
		{"stale", &domain.RejectionError{Reason: domain.ReasonStale, Message: "x"}, http.StatusUnauthorized},
		{"arn_not_allowed", &domain.RejectionError{Reason: domain.ReasonARNNotAllowed, Message: "x"}, http.StatusForbidden},
		{"verification_error", &sts.VerificationError{Reason: "서명 무효", HTTPStatus: 403}, http.StatusUnauthorized},
		{"infra", errors.New("STS 도달 불가"), http.StatusBadGateway},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAuthenticator{err: tc.err}

			rec := doAuth(newAuthEngine(fake), mustJSON(t, validEnvelope()))

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !fake.called {
				t.Error("코어가 호출되지 않음")
			}
		})
	}
}

// TestAuthenticate_endToEnd 는 실제 어댑터(정책/시계/STS/발급)를 조립해 /auth 경로를
// end-to-end 로 구동한다. STS 는 httptest TLS 서버로 흉내내 200 과 GetCallerIdentity XML 을
// 돌려주므로, 실제 SigV4 서명 없이도 위임 성공 경로를 검증할 수 있다.
func TestAuthenticate_endToEnd(t *testing.T) {
	const stsResp = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:role/workload</Arn>
    <UserId>AIDAEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`

	stsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, stsResp)
	}))
	defer stsSrv.Close()

	// 실제 어댑터 Load 가 읽는 viper 를 직접 구성한다. STS 허용 목록은 흉내 서버 URL 로 둔다.
	v := viper.New()
	v.Set("policy.binding_value", "https://server.example/audience")
	v.Set("policy.request_max_age", "5m")
	v.Set("policy.allowed_arns", "arn:aws:iam::123456789012:role/workload")
	v.Set("jwt.signing_secret", "sample-only-hs256-secret-change-me-in-real-deployments")
	v.Set("jwt.ttl", "15m")
	v.Set("jwt.issuer", "https://server.example")
	v.Set("jwt.audience", "https://server.example/clients")
	v.Set("sts.endpoint_allowlist", stsSrv.URL)

	policy, err := policyconfig.Load(v)
	if err != nil {
		t.Fatalf("정책 로드 실패: %v", err)
	}
	issuerParams, err := issuer.Load(v)
	if err != nil {
		t.Fatalf("발급 설정 로드 실패: %v", err)
	}
	verifier := sts.New(stsSrv.Client(), sts.LoadAllowedEndpoints(v))
	svc := domain.NewService(policy, clock.New(), verifier, issuer.New(issuerParams))
	engine := newAuthEngine(svc)

	// X-Amz-Date 는 현재 시각으로 둬 실제 시계 기준 신선도(5m)를 통과시킨다. url 은 흉내 STS.
	now := time.Now().UTC()
	env := authRequest{
		Method: "POST",
		URL:    stsSrv.URL,
		Headers: map[string][]string{
			"Authorization":    {"AWS4-HMAC-SHA256 Credential=AKID/20260708/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date;x-server-binding, Signature=abcd"},
			"X-Amz-Date":       {now.Format(amzDateFormat)},
			"Host":             {"sts.local"},
			"X-Server-Binding": {"https://server.example/audience"},
			"Content-Type":     {"application/x-www-form-urlencoded"},
		},
		Body: base64.StdEncoding.EncodeToString([]byte("Action=GetCallerIdentity&Version=2011-06-15")),
	}

	rec := doAuth(engine, mustJSON(t, env))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("응답 파싱 실패: %v", err)
	}
	if parts := strings.Split(resp.Token, "."); len(parts) != 3 {
		t.Errorf("발급 토큰이 JWT(3 세그먼트) 형태가 아님: %q", resp.Token)
	}
	if resp.ExpiresAt == "" {
		t.Error("expires_at 이 비어 있음")
	}
}
