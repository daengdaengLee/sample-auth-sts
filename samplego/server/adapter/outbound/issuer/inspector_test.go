package issuer

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// newTestInspector 는 테스트 시크릿으로 Inspector 를 만든다. 발급(newTestIssuer)과 같은
// testSecret 을 써, 왕복(발급 -> 검증)이 성공하는 기준을 만든다.
func newTestInspector(secret []byte) *Inspector {
	return NewInspector(Params{
		Secret:   secret,
		Issuer:   "https://server.example",
		Audience: "https://server.example/clients",
	})
}

// issueTestToken 은 고정 시각 발급기로 토큰 한 건을 만들어 돌려준다.
func issueTestToken(t *testing.T, ttl time.Duration, id domain.Identity) string {
	t.Helper()
	cred, err := newTestIssuer(ttl).IssueCredential(context.Background(), id)
	if err != nil {
		t.Fatalf("IssueCredential 에러: %v", err)
	}
	return cred.Token
}

// TestInspect_roundTrip 은 발급한 토큰을 같은 시크릿의 검사기로 검증하면 클레임이 정확히
// 되살아나는지 확인한다(발급/검증 대칭). 시각 클레임은 초 단위로 복원되는지도 본다.
func TestInspect_roundTrip(t *testing.T) {
	ttl := 10 * time.Minute
	id := domain.Identity{
		ARN:     "arn:aws:iam::123456789012:role/workload",
		Account: "123456789012",
		UserID:  "AIDAEXAMPLE",
	}
	token := issueTestToken(t, ttl, id)

	vt, err := newTestInspector(testSecret).Inspect(context.Background(), token)
	if err != nil {
		t.Fatalf("Inspect 에러: %v", err)
	}

	if vt.Issuer != "https://server.example" {
		t.Errorf("Issuer = %q", vt.Issuer)
	}
	if vt.Subject != id.ARN {
		t.Errorf("Subject = %q, want %q", vt.Subject, id.ARN)
	}
	if vt.Audience != "https://server.example/clients" {
		t.Errorf("Audience = %q", vt.Audience)
	}
	if vt.Account != id.Account {
		t.Errorf("Account = %q", vt.Account)
	}
	if vt.UserID != id.UserID {
		t.Errorf("UserID = %q", vt.UserID)
	}
	if vt.JTI == "" {
		t.Error("JTI 가 비어 있음")
	}
	if vt.IssuedAt.Unix() != fixedTime.Unix() {
		t.Errorf("IssuedAt = %d, want %d", vt.IssuedAt.Unix(), fixedTime.Unix())
	}
	if want := fixedTime.Unix() + int64(ttl.Seconds()); vt.ExpiresAt.Unix() != want {
		t.Errorf("ExpiresAt = %d, want iat+ttl=%d", vt.ExpiresAt.Unix(), want)
	}
}

// TestInspect_forgedSignature 는 다른 시크릿으로 검증하면(= 서명 위조와 동치) 무효로 거부되는지
// 확인한다. 무효는 도메인 계약에 따라 *domain.VerificationRejected 여야 한다.
func TestInspect_forgedSignature(t *testing.T) {
	token := issueTestToken(t, 5*time.Minute, domain.Identity{ARN: "arn:aws:iam::123456789012:role/workload"})

	_, err := newTestInspector([]byte("wrong-secret-0123456789abcdef012")).Inspect(context.Background(), token)
	assertVerificationRejected(t, err)
}

// TestInspect_tamperedPayload 는 페이로드를 변조하면(서명 입력이 달라져) 서명 불일치로 거부되는지
// 확인한다.
func TestInspect_tamperedPayload(t *testing.T) {
	token := issueTestToken(t, 5*time.Minute, domain.Identity{ARN: "arn:aws:iam::123456789012:role/workload"})
	parts := strings.Split(token, ".")

	// 페이로드 세그먼트의 첫 글자를 다른 글자로 바꿔 서명 입력을 어긋나게 한다.
	seg := []byte(parts[1])
	if seg[0] == 'A' {
		seg[0] = 'B'
	} else {
		seg[0] = 'A'
	}
	tampered := parts[0] + "." + string(seg) + "." + parts[2]

	_, err := newTestInspector(testSecret).Inspect(context.Background(), tampered)
	assertVerificationRejected(t, err)
}

// TestInspect_tamperedHeaderAlg 는 헤더를 alg=none 등으로 바꾸면 고정 헤더 불일치로 거부되는지
// 확인한다(alg 변조 차단).
func TestInspect_tamperedHeaderAlg(t *testing.T) {
	token := issueTestToken(t, 5*time.Minute, domain.Identity{ARN: "arn:aws:iam::123456789012:role/workload"})
	parts := strings.Split(token, ".")

	forgedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	tampered := forgedHeader + "." + parts[1] + "." + parts[2]

	_, err := newTestInspector(testSecret).Inspect(context.Background(), tampered)
	assertVerificationRejected(t, err)
}

// TestInspect_malformedStructure 는 세그먼트 수 오류/잘린 토큰이 무효로 거부되는지 표로 확인한다.
func TestInspect_malformedStructure(t *testing.T) {
	valid := issueTestToken(t, 5*time.Minute, domain.Identity{ARN: "arn:aws:iam::123456789012:role/workload"})
	parts := strings.Split(valid, ".")

	cases := []struct {
		name  string
		token string
	}{
		{"빈 문자열", ""},
		{"세그먼트 1개", parts[0]},
		{"세그먼트 2개", parts[0] + "." + parts[1]},
		{"세그먼트 4개", valid + ".extra"},
		{"서명 세그먼트 잘림", parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-5]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestInspector(testSecret).Inspect(context.Background(), tc.token)
			assertVerificationRejected(t, err)
		})
	}
}

// assertVerificationRejected 는 err 가 *domain.VerificationRejected 인지 확인하는 테스트 헬퍼다.
func assertVerificationRejected(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("에러가 nil (무효 토큰인데 통과함)")
	}
	if _, ok := domain.AsVerificationRejected(err); !ok {
		t.Fatalf("err 가 *domain.VerificationRejected 가 아님: %v", err)
	}
}
