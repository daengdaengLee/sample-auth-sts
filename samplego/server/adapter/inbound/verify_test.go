package inbound

import (
	"bytes"
	"context"
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

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/issuer"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/config/configtest"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/logging"
)

// fakeTokenVerifier 는 인바운드 검증 포트 대역이다. 주입한 결과/에러를 돌려주고, 호출 여부와
// 넘어온 입력을 기록해 HTTP 매핑과 파싱 결과를 격리 검증한다.
type fakeTokenVerifier struct {
	out    domain.VerifyTokenOutput
	err    error
	called bool
	gotIn  domain.VerifyTokenInput
}

func (f *fakeTokenVerifier) VerifyToken(_ context.Context, in domain.VerifyTokenInput) (domain.VerifyTokenOutput, error) {
	f.called = true
	f.gotIn = in
	return f.out, f.err
}

// newVerifyEngine 은 대역 검증 포트를 주입한 라우터를 만든다. /verify 테스트는 인증 포트를
// 쓰지 않으므로 auth 는 nil 로 둔다. 로그는 버린다.
func newVerifyEngine(verify domain.TokenVerifier) *gin.Engine {
	return NewRouter(logging.New(io.Discard, slog.LevelInfo), nil, verify)
}

// doVerify 는 주어진 JSON 본문으로 /verify 를 호출한 결과를 돌려준다.
func doVerify(engine *gin.Engine, jsonBody []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// TestVerify_success 는 성공 시 200 과 클레임이 응답되고, 요청 token 이 코어로 넘어가는지
// 확인한다.
func TestVerify_success(t *testing.T) {
	exp := time.Date(2026, 7, 8, 12, 15, 0, 0, time.UTC)
	iat := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	fake := &fakeTokenVerifier{out: domain.VerifyTokenOutput{Claims: domain.VerifiedToken{
		Issuer:    "https://server.example",
		Subject:   "arn:aws:iam::123456789012:role/workload",
		Audience:  "https://server.example/clients",
		ExpiresAt: exp,
		IssuedAt:  iat,
		JTI:       "jti-1",
		Account:   "123456789012",
		UserID:    "AIDAEXAMPLE",
	}}}

	rec := doVerify(newVerifyEngine(fake), mustJSON(t, verifyRequest{Token: "header.payload.sig"}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp verifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("응답 파싱 실패: %v", err)
	}
	if resp.Subject != "arn:aws:iam::123456789012:role/workload" {
		t.Errorf("sub = %q", resp.Subject)
	}
	if resp.Issuer != "https://server.example" {
		t.Errorf("iss = %q", resp.Issuer)
	}
	if resp.Audience != "https://server.example/clients" {
		t.Errorf("aud = %q", resp.Audience)
	}
	if resp.ExpiresAt != exp.Format(time.RFC3339) {
		t.Errorf("exp = %q, want %q", resp.ExpiresAt, exp.Format(time.RFC3339))
	}
	if resp.IssuedAt != iat.Format(time.RFC3339) {
		t.Errorf("iat = %q, want %q", resp.IssuedAt, iat.Format(time.RFC3339))
	}
	if resp.JTI != "jti-1" || resp.Account != "123456789012" || resp.UserID != "AIDAEXAMPLE" {
		t.Errorf("부가 클레임 매핑 오류: jti=%q account=%q user_id=%q", resp.JTI, resp.Account, resp.UserID)
	}

	if !fake.called {
		t.Fatal("검증 포트가 호출되지 않음")
	}
	if fake.gotIn.Token != "header.payload.sig" {
		t.Errorf("코어로 넘어간 token = %q", fake.gotIn.Token)
	}
}

// TestVerify_errorMapping 은 코어/어댑터가 돌려준 에러가 올바른 HTTP 상태로 매핑되는지 표로
// 확인한다. 무효 토큰(서명/구조, 만료/클레임 불일치)은 401, 내부 오류는 500 이다.
func TestVerify_errorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"서명/구조 무효(VerificationRejected)", &domain.VerificationRejected{Reason: "서명 불일치"}, http.StatusUnauthorized},
		{"만료(RejectionError)", &domain.RejectionError{Reason: domain.ReasonTokenExpired, Message: "x"}, http.StatusUnauthorized},
		{"iss 불일치(RejectionError)", &domain.RejectionError{Reason: domain.ReasonIssuerMismatch, Message: "x"}, http.StatusUnauthorized},
		{"aud 불일치(RejectionError)", &domain.RejectionError{Reason: domain.ReasonAudienceMismatch, Message: "x"}, http.StatusUnauthorized},
		{"내부 오류", errors.New("예상치 못한 오류"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeTokenVerifier{err: tc.err}

			rec := doVerify(newVerifyEngine(fake), mustJSON(t, verifyRequest{Token: "t"}))

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !fake.called {
				t.Error("코어가 호출되지 않음")
			}
		})
	}
}

// TestVerify_badRequest 는 요청 엔벨로프 오류(빈 토큰/JSON 불량/상한 초과)가 도메인 호출 전에
// 올바른 4xx 로 거르고, 코어를 호출하지 않는지 확인한다.
func TestVerify_badRequest(t *testing.T) {
	t.Run("빈 토큰은 400", func(t *testing.T) {
		fake := &fakeTokenVerifier{}
		rec := doVerify(newVerifyEngine(fake), mustJSON(t, verifyRequest{Token: ""}))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		if fake.called {
			t.Error("빈 토큰인데 코어가 호출됨")
		}
	})

	t.Run("JSON 불량은 400", func(t *testing.T) {
		fake := &fakeTokenVerifier{}
		rec := doVerify(newVerifyEngine(fake), []byte("{not json"))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		if fake.called {
			t.Error("파싱 실패인데 코어가 호출됨")
		}
	})

	t.Run("본문 상한 초과는 413", func(t *testing.T) {
		fake := &fakeTokenVerifier{}
		huge := `{"token":"` + strings.Repeat("A", maxAuthBodyBytes) + `"}`
		rec := doVerify(newVerifyEngine(fake), []byte(huge))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413 (body=%s)", rec.Code, rec.Body.String())
		}
		if fake.called {
			t.Error("상한 초과인데 코어가 호출됨")
		}
	})
}

// TestVerify_endToEnd 는 실제 어댑터(발급/검사)와 도메인 검증 서비스를 조립해 /verify 경로를
// end-to-end 로 구동한다. 유효 토큰은 200+클레임, 위조 서명/만료/클레임 불일치는 401 이다.
func TestVerify_endToEnd(t *testing.T) {
	// 실제 공유 로더와 같은 배선을 타는 configtest.Loader 로 발급 설정을 만든다.
	v := configtest.Loader(t, `
jwt:
  signing_secret: "sample-only-hs256-secret-change-me-in-real-deployments"
  ttl: "15m"
  issuer: "https://server.example"
  audience: "https://server.example/clients"
`)
	params, err := issuer.Load(v)
	if err != nil {
		t.Fatalf("발급 설정 로드 실패: %v", err)
	}

	// 발급 직전 시각을 기준으로 잡아, 만료 검증에 쓸 미래 고정 시각을 결정적으로 만든다.
	beforeIssue := time.Now()
	iss := issuer.New(params)
	cred, err := iss.IssueCredential(context.Background(), domain.Identity{
		ARN:     "arn:aws:iam::123456789012:role/workload",
		Account: "123456789012",
		UserID:  "AIDAEXAMPLE",
	})
	if err != nil {
		t.Fatalf("토큰 발급 실패: %v", err)
	}
	inspector := issuer.NewInspector(params)

	t.Run("유효 토큰은 200", func(t *testing.T) {
		// 발급 시각 직후의 고정 시계를 써, ttl(15m) 안이라 만료되지 않는다.
		svc := domain.NewVerifyService(fixedClock{t: beforeIssue}, inspector, params.Issuer, params.Audience)
		rec := doVerify(newVerifyEngine(svc), mustJSON(t, verifyRequest{Token: cred.Token}))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		var resp verifyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("응답 파싱 실패: %v", err)
		}
		if resp.Subject != "arn:aws:iam::123456789012:role/workload" {
			t.Errorf("sub = %q", resp.Subject)
		}
		if resp.Issuer != "https://server.example" || resp.Audience != "https://server.example/clients" {
			t.Errorf("iss/aud 매핑 오류: iss=%q aud=%q", resp.Issuer, resp.Audience)
		}
	})

	t.Run("위조 서명은 401", func(t *testing.T) {
		svc := domain.NewVerifyService(fixedClock{t: beforeIssue}, inspector, params.Issuer, params.Audience)
		parts := strings.Split(cred.Token, ".")
		// 서명 세그먼트의 첫 글자를 바꿔 위조한다.
		sig := []byte(parts[2])
		if sig[0] == 'A' {
			sig[0] = 'B'
		} else {
			sig[0] = 'A'
		}
		forged := parts[0] + "." + parts[1] + "." + string(sig)

		rec := doVerify(newVerifyEngine(svc), mustJSON(t, verifyRequest{Token: forged}))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("만료 토큰은 401", func(t *testing.T) {
		// 발급 시각보다 20분 뒤의 고정 시계로 검증하면 ttl(15m)을 지나 만료다.
		svc := domain.NewVerifyService(fixedClock{t: beforeIssue.Add(20 * time.Minute)}, inspector, params.Issuer, params.Audience)
		rec := doVerify(newVerifyEngine(svc), mustJSON(t, verifyRequest{Token: cred.Token}))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("클레임 불일치는 401", func(t *testing.T) {
		// 대상(aud) 기대값을 다르게 주입하면 aud 불일치로 거부된다.
		svc := domain.NewVerifyService(fixedClock{t: beforeIssue}, inspector, params.Issuer, "https://other.example/clients")
		rec := doVerify(newVerifyEngine(svc), mustJSON(t, verifyRequest{Token: cred.Token}))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
		}
	})
}
