package inbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	policyconfig "github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/config"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/issuer"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/sts"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/config/configtest"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/logging"
)

// fixedClock 는 신선도 검증을 결정적으로 만들기 위한 domain.Clock 구현이다. e2e 테스트가 실제
// 벽시계 대신 고정 시각을 쓰도록 한다.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

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

// newAuthEngine 은 대역 포트를 주입한 라우터를 만든다. 로그는 버린다. /auth 테스트는 검증
// 포트를 쓰지 않지만 NewRouter 가 두 포트를 모두 요구하므로, 미사용 verify 는 대역으로 채운다.
func newAuthEngine(auth domain.Authenticator) *gin.Engine {
	return NewRouter(logging.New(io.Discard, slog.LevelInfo), auth, &fakeTokenVerifier{})
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

// presignedQuery 는 모든 사전검증을 통과하는 기준 presigned 쿼리 파라미터를 만든다. 서버는
// 서명을 검증하지 않고 파라미터의 존재/형식/서명 범위만 보므로, 서명값은 임의 문자열로 둔다.
// X-Amz-SignedHeaders 에 host 와 x-server-binding 을 모두 넣어 바인딩이 서명 범위에 들게 한다.
func presignedQuery() url.Values {
	q := url.Values{}
	q.Set("Action", "GetCallerIdentity")
	q.Set("Version", "2011-06-15")
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", "AKID/20260708/us-east-1/sts/aws4_request")
	q.Set("X-Amz-Date", "20260708T120000Z")
	q.Set("X-Amz-Expires", "60")
	q.Set("X-Amz-SignedHeaders", "host;x-server-binding")
	q.Set("X-Amz-Signature", "abcd")
	return q
}

// presignedEnvelopeFrom 은 주어진 쿼리로 presigned authRequest 를 만든다. presigned 는 인증
// 정보를 URL 쿼리에 싣고(Authorization 헤더 없음), 헤더로는 서명 범위에 든 X-Server-Binding 과
// Host 만 보내며, body 는 빈 값이다.
func presignedEnvelopeFrom(q url.Values) authRequest {
	return authRequest{
		Method: "GET",
		URL:    "https://sts.amazonaws.com/?" + q.Encode(),
		Headers: map[string][]string{
			"Host":             {"sts.amazonaws.com"},
			"X-Server-Binding": {"https://server.example/audience"},
		},
		Body: "",
	}
}

// validPresignedEnvelope 는 모든 사전검증을 통과하는 기준 presigned 엔벨로프를 만든다.
func validPresignedEnvelope() authRequest {
	return presignedEnvelopeFrom(presignedQuery())
}

// TestAuthenticate_presignedSuccess 는 presigned 엔벨로프에서 SignedRequest 필드(Form/Method/
// Action/SignedAt/Expiry/BindingValue)가 올바로 유도돼 코어로 넘어가는지 확인한다.
func TestAuthenticate_presignedSuccess(t *testing.T) {
	exp := time.Date(2026, 7, 8, 12, 15, 0, 0, time.UTC)
	fake := &fakeAuthenticator{out: domain.AuthenticateOutput{
		Credential: domain.Credential{Token: "issued.jwt.token", ExpiresAt: exp},
	}}

	env := validPresignedEnvelope()
	rec := doAuth(newAuthEngine(fake), mustJSON(t, env))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !fake.called {
		t.Fatal("인바운드 포트가 호출되지 않음")
	}
	sr := fake.gotIn.Request
	if sr.Form != domain.FormPresigned {
		t.Errorf("Form = %q, want presigned", sr.Form)
	}
	if sr.Method != "GET" {
		t.Errorf("Method = %q, want GET", sr.Method)
	}
	if sr.Action != "GetCallerIdentity" {
		t.Errorf("Action = %q, want GetCallerIdentity", sr.Action)
	}
	if sr.BindingValue != "https://server.example/audience" {
		t.Errorf("BindingValue = %q", sr.BindingValue)
	}
	wantAt := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	if !sr.SignedAt.Equal(wantAt) {
		t.Errorf("SignedAt = %v, want %v", sr.SignedAt, wantAt)
	}
	if sr.Expiry != 60*time.Second {
		t.Errorf("Expiry = %v, want 60s", sr.Expiry)
	}
	// 원본 요청이 재구성 없이 그대로 위임되도록 넘어가는지 확인한다.
	if sr.Original.Method != "GET" || sr.Original.URL != env.URL {
		t.Errorf("Original(method=%q, url=%q) 가 엔벨로프와 다름", sr.Original.Method, sr.Original.URL)
	}
}

// TestAuthenticate_presignedExpiryBoundary 는 정확히 상한(MaxPresignExpirySeconds)인 X-Amz-Expires
// 가 수락되어 코어로 넘어가는지 확인한다. 상한 검사가 실수로 > 대신 >= 가 되는 off-by-one 회귀가
// 나면(경계값 거부) 이 테스트가 실패한다. 초과(604801)/거대값 거부는 preValidation 표가 덮는다.
func TestAuthenticate_presignedExpiryBoundary(t *testing.T) {
	fake := &fakeAuthenticator{out: domain.AuthenticateOutput{
		Credential: domain.Credential{Token: "t", ExpiresAt: time.Unix(0, 0)},
	}}

	q := presignedQuery()
	q.Set("X-Amz-Expires", fmt.Sprintf("%d", MaxPresignExpirySeconds))
	env := presignedEnvelopeFrom(q)

	rec := doAuth(newAuthEngine(fake), mustJSON(t, env))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (경계값 상한은 수락되어야 함, body=%s)", rec.Code, rec.Body.String())
	}
	if !fake.called {
		t.Fatal("경계값 상한인데 코어가 호출되지 않음")
	}
	if got, want := fake.gotIn.Request.Expiry, time.Duration(MaxPresignExpirySeconds)*time.Second; got != want {
		t.Errorf("Expiry = %v, want %v", got, want)
	}
}

// TestAuthenticate_presignedPreValidation 은 presigned 사전검증 실패가 올바른 상태로 매핑되고,
// 코어를 호출하지 않는지 표로 확인한다. 쿼리는 presignedQuery 를 기준으로 필요한 것만 바꾼다.
func TestAuthenticate_presignedPreValidation(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(e *authRequest)
		wantStatus int
	}{
		{
			name:       "X-Amz-Algorithm 부재(형태 판별 불가)",
			mutate:     func(e *authRequest) { *e = presignedEnvelopeFrom(without(presignedQuery(), "X-Amz-Algorithm")) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "X-Amz-Credential 부재",
			mutate:     func(e *authRequest) { *e = presignedEnvelopeFrom(without(presignedQuery(), "X-Amz-Credential")) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "X-Amz-Signature 부재",
			mutate:     func(e *authRequest) { *e = presignedEnvelopeFrom(without(presignedQuery(), "X-Amz-Signature")) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "X-Amz-SignedHeaders 에 x-server-binding 미포함",
			mutate: func(e *authRequest) {
				q := presignedQuery()
				q.Set("X-Amz-SignedHeaders", "host")
				*e = presignedEnvelopeFrom(q)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "X-Server-Binding 헤더 부재",
			mutate: func(e *authRequest) {
				*e = validPresignedEnvelope()
				delete(e.Headers, "X-Server-Binding")
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "X-Amz-Date 부재",
			mutate:     func(e *authRequest) { *e = presignedEnvelopeFrom(without(presignedQuery(), "X-Amz-Date")) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "X-Amz-Date 형식 불량",
			mutate: func(e *authRequest) {
				q := presignedQuery()
				q.Set("X-Amz-Date", "not-a-date")
				*e = presignedEnvelopeFrom(q)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "X-Amz-Expires 부재",
			mutate:     func(e *authRequest) { *e = presignedEnvelopeFrom(without(presignedQuery(), "X-Amz-Expires")) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "X-Amz-Expires 형식 불량",
			mutate: func(e *authRequest) {
				q := presignedQuery()
				q.Set("X-Amz-Expires", "abc")
				*e = presignedEnvelopeFrom(q)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "X-Amz-Expires 0 이하",
			mutate: func(e *authRequest) {
				q := presignedQuery()
				q.Set("X-Amz-Expires", "0")
				*e = presignedEnvelopeFrom(q)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "X-Amz-Expires 상한 초과",
			mutate: func(e *authRequest) {
				q := presignedQuery()
				// AWS presigned 최대 7일(604800s)을 넘긴다(오버플로/남용 방지 상한).
				q.Set("X-Amz-Expires", "604801")
				*e = presignedEnvelopeFrom(q)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "X-Amz-Expires 거대값(int64 초과)",
			mutate: func(e *authRequest) {
				q := presignedQuery()
				// int64 를 넘겨 strconv.Atoi 가 ErrRange 를 내는 경로(곱셈 오버플로 방지 계약 회귀).
				q.Set("X-Amz-Expires", "9999999999999999999")
				*e = presignedEnvelopeFrom(q)
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAuthenticator{}
			env := validPresignedEnvelope()
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

// without 는 쿼리에서 key 를 뺀 사본을 돌려준다(presigned 사전검증표에서 특정 파라미터 부재를
// 재현하는 데 쓴다).
func without(q url.Values, key string) url.Values {
	q.Del(key)
	return q
}

// TestAuthenticate_success 는 성공 시 200 과 발급 자격이 응답되고, 엔벨로프에서 SignedRequest
// 필드가 올바로 유도돼 코어로 넘어가는지 확인한다.
func TestAuthenticate_success(t *testing.T) {
	exp := time.Date(2026, 7, 8, 12, 15, 0, 0, time.UTC)
	fake := &fakeAuthenticator{out: domain.AuthenticateOutput{
		Credential: domain.Credential{Token: "issued.jwt.token", ExpiresAt: exp},
		Identity:   domain.Identity{ARN: "arn:aws:iam::123456789012:role/workload"},
	}}

	env := validEnvelope()
	rec := doAuth(newAuthEngine(fake), mustJSON(t, env))

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
	// STS 로 위임할 원본이 재구성 없이 그대로 넘어가는지 확인한다(이 핸들러의 보안 핵심).
	if sr.Original.Method != "POST" {
		t.Errorf("Original.Method = %q", sr.Original.Method)
	}
	if sr.Original.URL != "https://sts.amazonaws.com/" {
		t.Errorf("Original.URL = %q", sr.Original.URL)
	}
	if !reflect.DeepEqual(sr.Original.Header, env.Headers) {
		t.Errorf("Original.Header 가 엔벨로프 헤더와 다름:\n got=%v\nwant=%v", sr.Original.Header, env.Headers)
	}
	if got := string(sr.Original.Body); got != "Action=GetCallerIdentity&Version=2011-06-15" {
		t.Errorf("Original.Body = %q", got)
	}
}

// TestAuthenticate_duplicateActionIgnored 는 바디에 Action 이 중복되면(파라미터 오염) 핸들러가
// 첫 값을 묵시 채택하지 않고 빈 Action 을 코어로 넘겨, 코어가 형태 검증에서 거르게 하는지 본다.
func TestAuthenticate_duplicateActionIgnored(t *testing.T) {
	fake := &fakeAuthenticator{out: domain.AuthenticateOutput{
		Credential: domain.Credential{Token: "t", ExpiresAt: time.Unix(0, 0)},
	}}
	env := validEnvelope()
	env.Body = base64.StdEncoding.EncodeToString([]byte("Action=GetCallerIdentity&Action=AssumeRole&Version=2011-06-15"))

	doAuth(newAuthEngine(fake), mustJSON(t, env))

	if !fake.called {
		t.Fatal("코어가 호출되지 않음")
	}
	if got := fake.gotIn.Request.Action; got != "" {
		t.Errorf("중복 Action 인데 Action = %q, want \"\"(코어가 거르도록)", got)
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

// TestAuthenticate_bodyTooLarge 는 본문이 상한(maxBodyBytes)을 넘으면 413 이고 코어를
// 호출하지 않는지 확인한다(DoS 가드). MaxBytesReader 초과 -> *http.MaxBytesError -> 413.
func TestAuthenticate_bodyTooLarge(t *testing.T) {
	fake := &fakeAuthenticator{}
	// maxBodyBytes 를 확실히 넘기도록 body 필드에 큰 문자열을 채운 유효 JSON 을 만든다.
	huge := `{"method":"POST","body":"` + strings.Repeat("A", maxBodyBytes) + `"}`

	rec := doAuth(newAuthEngine(fake), []byte(huge))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413 (body=%s)", rec.Code, rec.Body.String())
	}
	if fake.called {
		t.Error("상한 초과인데 코어가 호출됨")
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
		{
			name:       "x-server-binding 대소문자 중복 키",
			mutate:     func(e *authRequest) { e.Headers["x-server-binding"] = []string{"https://evil.example/aud"} },
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "x-amz-date 대소문자 중복 키",
			mutate:     func(e *authRequest) { e.Headers["x-amz-date"] = []string{"20260708T120001Z"} },
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Authorization 중복 값",
			mutate: func(e *authRequest) {
				e.Headers["Authorization"] = append(e.Headers["Authorization"], "AWS4-HMAC-SHA256 ...")
			},
			wantStatus: http.StatusBadRequest,
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
		{"verification_error(sts wraps domain)", &sts.VerificationError{Reason: "서명 무효", HTTPStatus: 403}, http.StatusUnauthorized},
		{"verification_rejected(domain)", &domain.VerificationRejected{Reason: "서명 만료"}, http.StatusUnauthorized},
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

	// 흉내 STS 가 받은 요청을 캡처해, 위임된 원본이 재구성 없이 그대로 전달됐는지 확인한다.
	// round-trip 이 doAuth 반환 전에 끝나지만, 버퍼 채널로 동기화해 -race 에서도 안전하게 읽는다.
	type captured struct {
		method  string
		body    []byte
		binding string
	}
	gotReq := make(chan captured, 1)

	stsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := io.ReadAll(r.Body)
		gotReq <- captured{method: r.Method, body: reqBody, binding: r.Header.Get("X-Server-Binding")}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, stsResp)
	}))
	defer stsSrv.Close()

	// 실제 공유 로더와 같은 배선(yaml 파싱 + EnableEnvOverride)을 타는 configtest.Loader 로
	// viper 를 만든다. STS 허용 목록은 흉내 서버 URL 로 둔다.
	yamlBody := fmt.Sprintf(`
policy:
  binding_value: "https://server.example/audience"
  request_max_age: "5m"
  allowed_arns: "arn:aws:iam::123456789012:role/workload"
jwt:
  signing_secret: "sample-only-hs256-secret-change-me-in-real-deployments"
  ttl: "15m"
  issuer: "https://server.example"
  audience: "https://server.example/clients"
sts:
  endpoint_allowlist: "%s"
`, stsSrv.URL)
	v := configtest.Loader(t, yamlBody)

	policy, err := policyconfig.Load(v)
	if err != nil {
		t.Fatalf("정책 로드 실패: %v", err)
	}
	issuerParams, err := issuer.Load(v)
	if err != nil {
		t.Fatalf("발급 설정 로드 실패: %v", err)
	}
	verifier := sts.New(stsSrv.Client(), sts.LoadAllowedEndpoints(v))

	// 신선도를 결정적으로 만들려고 고정 시계를 쓴다. X-Amz-Date 를 이 기준 시각으로 두면 age 가
	// 0 이라 5m 창을 항상 통과한다.
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewService(policy, fixedClock{t: base}, verifier, issuer.New(issuerParams))
	engine := newAuthEngine(svc)

	const wantBody = "Action=GetCallerIdentity&Version=2011-06-15"
	env := authRequest{
		Method: "POST",
		URL:    stsSrv.URL,
		Headers: map[string][]string{
			"Authorization":    {"AWS4-HMAC-SHA256 Credential=AKID/20260708/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date;x-server-binding, Signature=abcd"},
			"X-Amz-Date":       {base.Format(amzDateFormat)},
			"Host":             {"sts.local"},
			"X-Server-Binding": {"https://server.example/audience"},
			"Content-Type":     {"application/x-www-form-urlencoded"},
		},
		Body: base64.StdEncoding.EncodeToString([]byte(wantBody)),
	}

	rec := doAuth(engine, mustJSON(t, env))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("응답 파싱 실패: %v", err)
	}
	// 발급 토큰의 payload 클레임이 issuer 설정에서 온 값인지 확인한다(설정 배선이 실제로
	// 반영되는지 검증. 3-세그먼트 형태 검사만으로는 iss/aud/ttl 오배선을 놓친다).
	parts := strings.Split(resp.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("발급 토큰이 JWT(3 세그먼트) 형태가 아님: %q", resp.Token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("JWT payload base64url 디코드 실패: %v", err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("JWT 클레임 파싱 실패: %v", err)
	}
	if claims.Iss != "https://server.example" {
		t.Errorf("iss = %q, want https://server.example", claims.Iss)
	}
	if claims.Aud != "https://server.example/clients" {
		t.Errorf("aud = %q, want https://server.example/clients", claims.Aud)
	}
	if claims.Sub != "arn:aws:iam::123456789012:role/workload" {
		t.Errorf("sub = %q, want 검증된 ARN", claims.Sub)
	}
	// exp - iat 로 ttl 배선을 검증한다. yaml 의 jwt.ttl 은 15m 이고 issuer 가 iat/exp 를 초
	// 단위로 계산하므로 차이는 정확히 900 이다(exp>0 만 보면 ttl 오배선을 놓친다).
	if got := claims.Exp - claims.Iat; got != 900 {
		t.Errorf("exp - iat = %d, want 900 (jwt.ttl=15m)", got)
	}
	if resp.ExpiresAt == "" {
		t.Error("expires_at 이 비어 있음")
	}

	// 위임된 원본이 그대로 전달됐는지 확인한다(포워딩 충실도). 스텁이 채널로 넘긴 값을 읽는다.
	select {
	case got := <-gotReq:
		if got.method != "POST" {
			t.Errorf("STS 로 위임된 메서드 = %q, want POST", got.method)
		}
		if string(got.body) != wantBody {
			t.Errorf("STS 로 위임된 바디 = %q, want %q", string(got.body), wantBody)
		}
		if got.binding != "https://server.example/audience" {
			t.Errorf("STS 로 위임된 X-Server-Binding = %q", got.binding)
		}
	default:
		t.Error("흉내 STS 가 요청을 받지 못함(위임이 일어나지 않음)")
	}
}
