package issuer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// testSecret 은 테스트에서 쓰는 32바이트 HS256 키다.
var testSecret = []byte("0123456789abcdef0123456789abcdef")

// fixedTime 은 iat/exp 를 결정적으로 만들기 위한 고정 시각이다.
var fixedTime = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

// newTestIssuer 는 고정 시각을 주입한 Issuer 를 만든다. now 는 미공개 필드이므로 같은
// package 인 테스트에서만 이렇게 덮어쓸 수 있다(공개 API 오염 없음).
func newTestIssuer(ttl time.Duration) *Issuer {
	iss := New(Params{
		Secret:   testSecret,
		TTL:      ttl,
		Issuer:   "https://server.example",
		Audience: "https://server.example/clients",
	})
	iss.now = func() time.Time { return fixedTime }
	return iss
}

// decodeSegment 는 base64url(no pad) 세그먼트를 디코드해 지정 구조로 언마샬한다.
func decodeSegment(t *testing.T, seg string, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("세그먼트 base64url 디코드 실패: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("세그먼트 JSON 언마샬 실패: %v", err)
	}
}

// TestIssueCredential_structureAndClaims 는 발급 토큰의 구조(3 세그먼트)와 헤더/클레임
// 매핑, iat/exp 및 반환 ExpiresAt 이 기대대로인지 확인한다.
func TestIssueCredential_structureAndClaims(t *testing.T) {
	ttl := 10 * time.Minute
	iss := newTestIssuer(ttl)

	cred, err := iss.IssueCredential(context.Background(), domain.Identity{
		ARN:     "arn:aws:iam::123456789012:role/workload",
		Account: "123456789012",
		UserID:  "AIDAEXAMPLE",
	})
	if err != nil {
		t.Fatalf("IssueCredential 에러: %v", err)
	}

	parts := strings.Split(cred.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("토큰 세그먼트 수=%d, want 3", len(parts))
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	decodeSegment(t, parts[0], &header)
	if header.Alg != "HS256" || header.Typ != "JWT" {
		t.Errorf("헤더가 기대와 다름: alg=%q typ=%q", header.Alg, header.Typ)
	}

	var c claims
	decodeSegment(t, parts[1], &c)
	if c.Iss != "https://server.example" {
		t.Errorf("iss=%q", c.Iss)
	}
	if c.Sub != "arn:aws:iam::123456789012:role/workload" {
		t.Errorf("sub(=ARN)=%q", c.Sub)
	}
	if c.Aud != "https://server.example/clients" {
		t.Errorf("aud=%q", c.Aud)
	}
	if c.Account != "123456789012" {
		t.Errorf("account=%q", c.Account)
	}
	if c.UserID != "AIDAEXAMPLE" {
		t.Errorf("user_id=%q", c.UserID)
	}
	if c.Iat != fixedTime.Unix() {
		t.Errorf("iat=%d, want %d", c.Iat, fixedTime.Unix())
	}
	if want := fixedTime.Unix() + int64(ttl.Seconds()); c.Exp != want {
		t.Errorf("exp=%d, want iat+ttl=%d", c.Exp, want)
	}
	if c.Jti == "" {
		t.Error("jti 가 비어 있음")
	}
	if cred.ExpiresAt.Unix() != c.Exp {
		t.Errorf("ExpiresAt=%d, want exp=%d", cred.ExpiresAt.Unix(), c.Exp)
	}
}

// TestIssueCredential_signatureValid 는 세 번째 세그먼트가 header.payload 에 대한 HMAC-SHA256
// 서명과 일치하고, 다른 시크릿으로는 불일치하는지 확인한다.
func TestIssueCredential_signatureValid(t *testing.T) {
	iss := newTestIssuer(5 * time.Minute)

	cred, err := iss.IssueCredential(context.Background(), domain.Identity{ARN: "arn:aws:iam::123456789012:role/workload"})
	if err != nil {
		t.Fatalf("IssueCredential 에러: %v", err)
	}

	parts := strings.Split(cred.Token, ".")
	signingInput := parts[0] + "." + parts[1]
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("서명 세그먼트 디코드 실패: %v", err)
	}

	m := hmac.New(sha256.New, testSecret)
	m.Write([]byte(signingInput))
	if !hmac.Equal(gotSig, m.Sum(nil)) {
		t.Error("같은 시크릿으로 재계산한 서명이 토큰 서명과 일치하지 않음")
	}

	other := hmac.New(sha256.New, []byte("wrong-secret-0123456789abcdef012"))
	other.Write([]byte(signingInput))
	if hmac.Equal(gotSig, other.Sum(nil)) {
		t.Error("다른 시크릿으로 계산한 서명이 일치함(서명이 키에 묶이지 않음)")
	}
}

// TestIssueCredential_uniqueJTI 는 두 번 발급하면 jti 가 서로 다른지 확인한다(난수성).
func TestIssueCredential_uniqueJTI(t *testing.T) {
	iss := newTestIssuer(5 * time.Minute)
	id := domain.Identity{ARN: "arn:aws:iam::123456789012:role/workload"}

	first := issueClaims(t, iss, id)
	second := issueClaims(t, iss, id)
	if first.Jti == second.Jti {
		t.Errorf("두 발급의 jti 가 같음: %q", first.Jti)
	}
}

// TestIssueCredential_identityMapping 은 부가 정보가 빈 신원을 포함해 여러 신원의 클레임
// 매핑이 정확한지 확인한다.
func TestIssueCredential_identityMapping(t *testing.T) {
	iss := newTestIssuer(5 * time.Minute)

	cases := []domain.Identity{
		{ARN: "arn:aws:iam::111111111111:role/a", Account: "111111111111", UserID: "AIDA1"},
		{ARN: "arn:aws:iam::222222222222:user/b"}, // Account/UserID 비어 있음
	}
	for _, id := range cases {
		t.Run(id.ARN, func(t *testing.T) {
			c := issueClaims(t, iss, id)
			if c.Sub != id.ARN {
				t.Errorf("sub=%q, want %q", c.Sub, id.ARN)
			}
			if c.Account != id.Account {
				t.Errorf("account=%q, want %q", c.Account, id.Account)
			}
			if c.UserID != id.UserID {
				t.Errorf("user_id=%q, want %q", c.UserID, id.UserID)
			}
		})
	}
}

// issueClaims 는 발급 후 페이로드 클레임을 디코드해 돌려주는 테스트 헬퍼다.
func issueClaims(t *testing.T, iss *Issuer, id domain.Identity) claims {
	t.Helper()
	cred, err := iss.IssueCredential(context.Background(), id)
	if err != nil {
		t.Fatalf("IssueCredential 에러: %v", err)
	}
	parts := strings.Split(cred.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("토큰 세그먼트 수=%d, want 3", len(parts))
	}
	var c claims
	decodeSegment(t, parts[1], &c)
	return c
}
