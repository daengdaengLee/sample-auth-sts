package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/client/internal/proof"
)

// TestPostAuth_success 는 200 응답에서 토큰과 RFC3339 만료가 올바로 파싱되고, 요청이 JSON
// 엔벨로프로 /auth 에 POST 되는지 확인한다.
func TestPostAuth_success(t *testing.T) {
	exp := time.Date(2026, 7, 9, 12, 15, 0, 0, time.UTC)

	var gotPath, gotMethod, gotContentType string
	var gotEnvelope proof.Envelope

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotContentType = r.URL.Path, r.Method, r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotEnvelope)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"issued.jwt.token","expires_at":"`+exp.Format(time.RFC3339)+`"}`)
	}))
	defer srv.Close()

	env := proof.Envelope{Method: "POST", URL: "https://sts.amazonaws.com", Headers: map[string][]string{"Host": {"sts.amazonaws.com"}}, Body: "Zm9v"}
	res, err := New(srv.URL, nil).PostAuth(context.Background(), env)
	if err != nil {
		t.Fatalf("PostAuth 실패: %v", err)
	}

	if res.Token != "issued.jwt.token" {
		t.Errorf("Token = %q", res.Token)
	}
	if !res.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", res.ExpiresAt, exp)
	}
	if gotPath != "/auth" || gotMethod != http.MethodPost {
		t.Errorf("요청 = %s %s, want POST /auth", gotMethod, gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotEnvelope.Method != "POST" || gotEnvelope.Body != "Zm9v" {
		t.Errorf("서버가 받은 엔벨로프가 다름: %+v", gotEnvelope)
	}
}

// TestPostAuth_apiError 는 4xx 응답이 error/message/status 를 담은 *APIError 로 매핑되는지
// 확인한다.
func TestPostAuth_apiError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"binding_mismatch","message":"바인딩 불일치"}`)
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).PostAuth(context.Background(), proof.Envelope{})
	if err == nil {
		t.Fatal("에러가 없음, want *APIError")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("에러 타입 = %T, want *APIError", err)
	}
	if apiErr.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403", apiErr.Status)
	}
	if apiErr.Code != "binding_mismatch" {
		t.Errorf("Code = %q, want binding_mismatch", apiErr.Code)
	}
}

// TestPostAuth_badExpiresAt 은 만료가 RFC3339 가 아니면 에러를 내는지 확인한다.
func TestPostAuth_badExpiresAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"token":"t","expires_at":"not-a-time"}`)
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).PostAuth(context.Background(), proof.Envelope{})
	if err == nil {
		t.Fatal("잘못된 expires_at 인데 에러가 없음")
	}
}

// TestPostVerify_success 는 200 응답에서 클레임이 올바로 디코드되고, 토큰이 JSON 으로 /verify
// 에 POST 되는지 확인한다.
func TestPostVerify_success(t *testing.T) {
	var gotPath string
	var gotBody struct {
		Token string `json:"token"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"iss":"https://server.example","sub":"arn:aws:iam::123456789012:role/workload","aud":"https://server.example/clients","exp":"2026-07-09T12:15:00Z","iat":"2026-07-09T12:00:00Z","jti":"id-1","account":"123456789012","user_id":"AIDA"}`)
	}))
	defer srv.Close()

	claims, err := New(srv.URL, nil).PostVerify(context.Background(), "issued.jwt.token")
	if err != nil {
		t.Fatalf("PostVerify 실패: %v", err)
	}
	if gotPath != "/verify" {
		t.Errorf("path = %q, want /verify", gotPath)
	}
	if gotBody.Token != "issued.jwt.token" {
		t.Errorf("전송된 token = %q", gotBody.Token)
	}
	if claims.Issuer != "https://server.example" {
		t.Errorf("Issuer = %q", claims.Issuer)
	}
	if claims.Subject != "arn:aws:iam::123456789012:role/workload" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Account != "123456789012" {
		t.Errorf("Account = %q", claims.Account)
	}
}

// TestPostVerify_unauthorized 는 401 이 *APIError 로 매핑되는지 확인한다.
func TestPostVerify_unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_token","message":"토큰 검증 실패"}`)
	}))
	defer srv.Close()

	_, err := New(srv.URL, nil).PostVerify(context.Background(), "bad.token")
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("에러 타입 = %T, want *APIError", err)
	}
	if apiErr.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", apiErr.Status)
	}
}
