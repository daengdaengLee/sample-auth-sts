package domain

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// baseTime 은 테스트에서 시계와 서명 시각의 기준으로 쓰는 고정 시각이다.
var baseTime = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

const (
	testBinding = "https://server.example/audience"
	testARN     = "arn:aws:iam::123456789012:role/workload"
)

// validRequest 는 모든 로컬 검증을 통과하는 기준 SignedRequest 를 만든다. 각 테스트는
// 필요한 필드만 바꿔 특정 검증 실패를 재현한다.
func validRequest() SignedRequest {
	return SignedRequest{
		BindingValue: testBinding,
		Method:       "POST",
		Action:       "GetCallerIdentity",
		SignedAt:     baseTime.Add(-30 * time.Second),
		Original: PreservedRequest{
			Method: "POST",
			URL:    "https://sts.amazonaws.com/",
			Header: map[string][]string{"Authorization": {"AWS4-HMAC-SHA256 ..."}},
			Body:   []byte("Action=GetCallerIdentity&Version=2011-06-15"),
		},
	}
}

// defaultPolicy 는 기준 요청을 통과시키는 정책이다.
func defaultPolicy() fakePolicy {
	return fakePolicy{
		binding: testBinding,
		maxAge:  5 * time.Minute,
		allowed: map[string]bool{testARN: true},
	}
}

// newService 는 통과 기본값을 가진 포트로 Service 와 대역을 함께 만든다. 시계는 baseTime
// 에 고정한다. 호출자는 반환된 대역을 검사하거나 필드를 바꿔 실패 시나리오를 만든다.
func newService(policy Policy) (*Service, *fakeVerifier, *fakeIssuer) {
	verifier := &fakeVerifier{id: Identity{ARN: testARN}}
	issuer := &fakeIssuer{cred: Credential{Token: "issued-token", ExpiresAt: baseTime.Add(time.Hour)}}
	svc := NewService(policy, fakeClock{now: baseTime}, verifier, issuer)
	return svc, verifier, issuer
}

// TestService_Authenticate_success 는 모든 검증을 통과하면 자격이 발급되고, 두 아웃바운드
// 포트가 호출되며, 검증 결과 신원이 발급 포트로 그대로 넘어가는지 확인한다.
func TestService_Authenticate_success(t *testing.T) {
	svc, verifier, issuer := newService(defaultPolicy())

	out, err := svc.Authenticate(context.Background(), AuthenticateInput{Request: validRequest()})
	if err != nil {
		t.Fatalf("예상치 못한 에러: %v", err)
	}
	if !verifier.called {
		t.Error("신원 검증 포트가 호출되지 않음")
	}
	if !issuer.called {
		t.Error("자격 발급 포트가 호출되지 않음")
	}
	if out.Credential.Token != "issued-token" {
		t.Errorf("발급 자격이 기대와 다름: %q", out.Credential.Token)
	}
	if out.Identity.ARN != testARN {
		t.Errorf("반환 신원 ARN 이 기대와 다름: %q", out.Identity.ARN)
	}
	if issuer.gotID.ARN != testARN {
		t.Errorf("발급 포트에 넘긴 신원이 검증 결과와 다름: %q", issuer.gotID.ARN)
	}
}

// TestService_Authenticate_rejections 는 각 로컬 검증 실패가 올바른 거부 사유로 매핑되고,
// 네트워크 위임 앞 단계에서 걸린 경우 신원 검증 포트가 아예 호출되지 않으며, 어느 거부든
// 자격 발급으로 이어지지 않는지 표로 검증한다.
func TestService_Authenticate_rejections(t *testing.T) {
	cases := []struct {
		name         string
		policy       fakePolicy
		mutate       func(r *SignedRequest)
		wantReason   RejectionReason
		wantVerifier bool // 신원 검증 포트가 호출되어야 하는지
	}{
		{
			name:         "바인딩 불일치",
			policy:       defaultPolicy(),
			mutate:       func(r *SignedRequest) { r.BindingValue = "https://evil.example/aud" },
			wantReason:   ReasonBindingMismatch,
			wantVerifier: false,
		},
		{
			name:         "형태 불량 - 메서드",
			policy:       defaultPolicy(),
			mutate:       func(r *SignedRequest) { r.Method = "GET" },
			wantReason:   ReasonInvalidShape,
			wantVerifier: false,
		},
		{
			name:         "형태 불량 - 액션",
			policy:       defaultPolicy(),
			mutate:       func(r *SignedRequest) { r.Action = "AssumeRole" },
			wantReason:   ReasonInvalidShape,
			wantVerifier: false,
		},
		{
			name:         "만료 - age 초과",
			policy:       defaultPolicy(),
			mutate:       func(r *SignedRequest) { r.SignedAt = baseTime.Add(-10 * time.Minute) },
			wantReason:   ReasonStale,
			wantVerifier: false,
		},
		{
			name:         "만료 - 미래 시각",
			policy:       defaultPolicy(),
			mutate:       func(r *SignedRequest) { r.SignedAt = baseTime.Add(1 * time.Minute) },
			wantReason:   ReasonStale,
			wantVerifier: false,
		},
		{
			name:         "허용되지 않은 ARN",
			policy:       fakePolicy{binding: testBinding, maxAge: 5 * time.Minute, allowed: map[string]bool{}},
			mutate:       func(r *SignedRequest) {},
			wantReason:   ReasonARNNotAllowed,
			wantVerifier: true, // 위임 후 반환 ARN 을 대조하므로 검증 포트는 호출됨
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, verifier, issuer := newService(tc.policy)
			req := validRequest()
			tc.mutate(&req)

			_, err := svc.Authenticate(context.Background(), AuthenticateInput{Request: req})

			re, ok := AsRejection(err)
			if !ok {
				t.Fatalf("거부 에러가 아님: %v", err)
			}
			if re.Reason != tc.wantReason {
				t.Errorf("거부 사유 = %q, want %q", re.Reason, tc.wantReason)
			}
			if verifier.called != tc.wantVerifier {
				t.Errorf("verifier.called = %v, want %v", verifier.called, tc.wantVerifier)
			}
			if issuer.called {
				t.Error("거부되었는데 자격 발급 포트가 호출됨")
			}
		})
	}
}

// presignedRequest 는 모든 로컬 검증을 통과하는 기준 presigned SignedRequest 를 만든다.
// header 형태(validRequest)와 달리 Form=presigned, Method=GET 이고, 클라이언트가 지정한 만료
// (Expiry)를 담는다. 각 테스트는 필요한 필드만 바꿔 특정 검증 실패를 재현한다.
func presignedRequest() SignedRequest {
	req := validRequest()
	req.Form = FormPresigned
	req.Method = "GET"
	req.Expiry = 2 * time.Minute
	return req
}

// TestService_Authenticate_presignedSuccess 는 presigned 형태(GET + 클라이언트 만료)가 모든
// 검증을 통과해 자격이 발급되는지 확인한다(GET 이 형태 검증에서 거부되지 않아야 한다).
func TestService_Authenticate_presignedSuccess(t *testing.T) {
	svc, verifier, issuer := newService(defaultPolicy())

	_, err := svc.Authenticate(context.Background(), AuthenticateInput{Request: presignedRequest()})
	if err != nil {
		t.Fatalf("presigned 인데 예상치 못한 에러: %v", err)
	}
	if !verifier.called || !issuer.called {
		t.Error("presigned 성공 경로인데 위임/발급 포트가 호출되지 않음")
	}
}

// TestService_Authenticate_presignedShape 는 형태별 기대 메서드가 강제되는지 확인한다:
// presigned 는 GET 이어야 하고(POST 면 invalid_shape), header 는 POST 여야 한다(GET 면 invalid_shape).
func TestService_Authenticate_presignedShape(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *SignedRequest)
	}{
		{"presigned + POST 는 거부", func(r *SignedRequest) { *r = presignedRequest(); r.Method = "POST" }},
		{"header + GET 는 거부", func(r *SignedRequest) { *r = validRequest(); r.Method = "GET" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newService(defaultPolicy())
			var req SignedRequest
			tc.mutate(&req)

			_, err := svc.Authenticate(context.Background(), AuthenticateInput{Request: req})
			re, ok := AsRejection(err)
			if !ok {
				t.Fatalf("거부 에러가 아님: %v", err)
			}
			if re.Reason != ReasonInvalidShape {
				t.Errorf("거부 사유 = %q, want %q", re.Reason, ReasonInvalidShape)
			}
		})
	}
}

// TestService_Authenticate_presignedFreshness 는 presigned 유효 구간이 서버 최대 age 와 클라이언트
// 만료(Expiry)의 교집합(min)임을 확인한다. 서버 정책 maxAge 는 5m 고정(defaultPolicy).
func TestService_Authenticate_presignedFreshness(t *testing.T) {
	cases := []struct {
		name     string
		expiry   time.Duration
		age      time.Duration // baseTime - SignedAt
		wantPass bool
	}{
		// 클라이언트가 만료를 서버보다 짧게(1m) 잡으면 그만큼 창이 좁아진다.
		{"클라이언트 만료가 서버보다 짧고 그 안", 1 * time.Minute, 30 * time.Second, true},
		{"클라이언트 만료 초과(서버 max-age 안이라도 거부)", 1 * time.Minute, 2 * time.Minute, false},
		// 클라이언트가 만료를 서버보다 길게(10m) 잡아도 서버 max-age(5m)를 넘기면 거부된다(맹신 금지).
		{"서버 max-age 안", 10 * time.Minute, 4 * time.Minute, true},
		{"서버 max-age 초과(클라이언트 만료가 더 길어도 거부)", 10 * time.Minute, 7 * time.Minute, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newService(defaultPolicy())
			req := presignedRequest()
			req.Expiry = tc.expiry
			req.SignedAt = baseTime.Add(-tc.age)

			_, err := svc.Authenticate(context.Background(), AuthenticateInput{Request: req})
			if tc.wantPass {
				if err != nil {
					t.Fatalf("통과 기대인데 에러: %v", err)
				}
				return
			}
			re, ok := AsRejection(err)
			if !ok {
				t.Fatalf("거부 에러가 아님: %v", err)
			}
			if re.Reason != ReasonStale {
				t.Errorf("거부 사유 = %q, want %q", re.Reason, ReasonStale)
			}
		})
	}
}

// TestService_Authenticate_verifierError 는 신원 검증 포트의 인프라 실패가 거부가 아니라
// 원래 에러 그대로 전파되고, 자격 발급으로 이어지지 않는지 확인한다.
func TestService_Authenticate_verifierError(t *testing.T) {
	svc, verifier, issuer := newService(defaultPolicy())
	sentinel := errors.New("STS 도달 불가")
	verifier.err = sentinel

	_, err := svc.Authenticate(context.Background(), AuthenticateInput{Request: validRequest()})
	if !errors.Is(err, sentinel) {
		t.Fatalf("verifier 에러가 그대로 전파되지 않음: %v", err)
	}
	if _, ok := AsRejection(err); ok {
		t.Error("인프라 에러가 거부(RejectionError)로 잘못 분류됨")
	}
	if issuer.called {
		t.Error("신원 검증 실패 후 자격 발급 포트가 호출됨")
	}
}

// TestService_Authenticate_issuerError 는 자격 발급 포트의 실패가 거부가 아니라 원래 에러
// 그대로 전파되는지 확인한다.
func TestService_Authenticate_issuerError(t *testing.T) {
	svc, _, issuer := newService(defaultPolicy())
	sentinel := errors.New("발급 실패")
	issuer.err = sentinel

	_, err := svc.Authenticate(context.Background(), AuthenticateInput{Request: validRequest()})
	if !errors.Is(err, sentinel) {
		t.Fatalf("issuer 에러가 그대로 전파되지 않음: %v", err)
	}
	if _, ok := AsRejection(err); ok {
		t.Error("인프라 에러가 거부로 잘못 분류됨")
	}
}

// TestService_Authenticate_forwardsOriginalUnchanged 는 보존된 원본 서명 요청이 재구성
// 없이 신원 검증 포트로 그대로 넘어가는지 확인한다(양도 가능한 요청을 있는 그대로 위임).
func TestService_Authenticate_forwardsOriginalUnchanged(t *testing.T) {
	svc, verifier, _ := newService(defaultPolicy())
	req := validRequest()

	_, err := svc.Authenticate(context.Background(), AuthenticateInput{Request: req})
	if err != nil {
		t.Fatalf("예상치 못한 에러: %v", err)
	}
	if !reflect.DeepEqual(verifier.gotReq, req.Original) {
		t.Errorf("위임 포트에 넘긴 원본 요청이 입력과 다름:\n got=%+v\nwant=%+v", verifier.gotReq, req.Original)
	}
}
