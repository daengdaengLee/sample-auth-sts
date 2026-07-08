package domain

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeInspector 는 TokenInspector 포트의 테스트 대역이다. 주입한 결과/에러를 돌려주고,
// 호출 여부와 받은 토큰을 기록해 검증 서비스의 판단 논리를 격리 검증한다.
type fakeInspector struct {
	vt       VerifiedToken
	err      error
	called   bool
	gotToken string
}

func (f *fakeInspector) Inspect(_ context.Context, token string) (VerifiedToken, error) {
	f.called = true
	f.gotToken = token
	return f.vt, f.err
}

// verifyBaseTime 은 만료 판단을 결정적으로 만들기 위한 기준 시각이다.
var verifyBaseTime = time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

// validVerifiedToken 은 모든 로컬 검증(만료/발급자/대상)을 통과하는 기준 클레임을 만든다.
// 각 테스트는 필요한 필드만 바꿔 특정 실패를 재현한다.
func validVerifiedToken() VerifiedToken {
	return VerifiedToken{
		Issuer:    "https://server.example",
		Subject:   "arn:aws:iam::123456789012:role/workload",
		Audience:  "https://server.example/clients",
		ExpiresAt: verifyBaseTime.Add(5 * time.Minute),
		IssuedAt:  verifyBaseTime.Add(-1 * time.Minute),
		JTI:       "jti-1",
		Account:   "123456789012",
		UserID:    "AIDAEXAMPLE",
	}
}

// newVerifyService 는 고정 시계와 기준 기대값(iss/aud)으로 검증 서비스를 만든다.
func newVerifyService(inspector TokenInspector) *VerifyService {
	return NewVerifyService(fakeClock{now: verifyBaseTime}, inspector, "https://server.example", "https://server.example/clients")
}

// TestVerifyToken_success 는 서명(검사기)이 통과하고 만료/발급자/대상이 모두 맞으면 클레임이
// 그대로 돌려지고, 검사기에 원본 토큰이 넘어가는지 확인한다.
func TestVerifyToken_success(t *testing.T) {
	insp := &fakeInspector{vt: validVerifiedToken()}
	svc := newVerifyService(insp)

	out, err := svc.VerifyToken(context.Background(), VerifyTokenInput{Token: "header.payload.sig"})
	if err != nil {
		t.Fatalf("VerifyToken 에러: %v", err)
	}
	if !insp.called {
		t.Fatal("검사기가 호출되지 않음")
	}
	if insp.gotToken != "header.payload.sig" {
		t.Errorf("검사기에 넘어간 토큰 = %q", insp.gotToken)
	}
	if out.Claims.Subject != "arn:aws:iam::123456789012:role/workload" {
		t.Errorf("Subject = %q", out.Claims.Subject)
	}
	if out.Claims.Issuer != "https://server.example" {
		t.Errorf("Issuer = %q", out.Claims.Issuer)
	}
}

// TestVerifyToken_expiry 는 만료 경계를 표로 확인한다. now == exp 는 만료(exp 경과)로 본다.
func TestVerifyToken_expiry(t *testing.T) {
	cases := []struct {
		name    string
		exp     time.Time
		wantErr bool
	}{
		{"아직 유효(now < exp)", verifyBaseTime.Add(time.Second), false},
		{"경계(now == exp)는 만료", verifyBaseTime, true},
		{"이미 만료(now > exp)", verifyBaseTime.Add(-time.Second), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vt := validVerifiedToken()
			vt.ExpiresAt = tc.exp
			svc := newVerifyService(&fakeInspector{vt: vt})

			_, err := svc.VerifyToken(context.Background(), VerifyTokenInput{Token: "t"})
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("유효 토큰인데 에러: %v", err)
				}
				return
			}
			re, ok := AsRejection(err)
			if !ok {
				t.Fatalf("err 가 *RejectionError 가 아님: %v", err)
			}
			if re.Reason != ReasonTokenExpired {
				t.Errorf("Reason = %q, want %q", re.Reason, ReasonTokenExpired)
			}
		})
	}
}

// TestVerifyToken_claimMismatch 는 iss/aud 불일치가 각각의 사유로 거부되는지 확인한다.
func TestVerifyToken_claimMismatch(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(vt *VerifiedToken)
		wantReason RejectionReason
	}{
		{"iss 불일치", func(vt *VerifiedToken) { vt.Issuer = "https://evil.example" }, ReasonIssuerMismatch},
		{"aud 불일치", func(vt *VerifiedToken) { vt.Audience = "https://evil.example/clients" }, ReasonAudienceMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vt := validVerifiedToken()
			tc.mutate(&vt)
			svc := newVerifyService(&fakeInspector{vt: vt})

			_, err := svc.VerifyToken(context.Background(), VerifyTokenInput{Token: "t"})
			re, ok := AsRejection(err)
			if !ok {
				t.Fatalf("err 가 *RejectionError 가 아님: %v", err)
			}
			if re.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", re.Reason, tc.wantReason)
			}
		})
	}
}

// TestVerifyToken_inspectorRejectionPropagated 는 검사기가 낸 무효(*VerificationRejected)가
// 그대로 전파되고, 코어가 로컬 거부로 바꾸지 않는지 확인한다(수신 어댑터가 401 로 매핑).
func TestVerifyToken_inspectorRejectionPropagated(t *testing.T) {
	insp := &fakeInspector{err: &VerificationRejected{Reason: "서명 불일치"}}
	svc := newVerifyService(insp)

	_, err := svc.VerifyToken(context.Background(), VerifyTokenInput{Token: "t"})
	if _, ok := AsVerificationRejected(err); !ok {
		t.Fatalf("err 가 *VerificationRejected 가 아님: %v", err)
	}
	if _, ok := AsRejection(err); ok {
		t.Error("무효 토큰이 로컬 거부(*RejectionError)로 바뀜")
	}
}

// TestVerifyToken_inspectorInfraErrorPropagated 는 검사기의 내부 실패(일반 에러)가 거부로
// 바뀌지 않고 그대로 전파되는지 확인한다(수신 어댑터가 5xx 로 매핑).
func TestVerifyToken_inspectorInfraErrorPropagated(t *testing.T) {
	sentinel := errors.New("내부 오류")
	svc := newVerifyService(&fakeInspector{err: sentinel})

	_, err := svc.VerifyToken(context.Background(), VerifyTokenInput{Token: "t"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want 원본 에러 전파", err)
	}
	if _, ok := AsRejection(err); ok {
		t.Error("내부 오류가 로컬 거부로 바뀜")
	}
	if _, ok := AsVerificationRejected(err); ok {
		t.Error("내부 오류가 무효 토큰으로 바뀜")
	}
}
