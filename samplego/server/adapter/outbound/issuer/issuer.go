// Package issuer 는 README 헥사고날 설계의 "자격 발급 어댑터(아웃바운드 어댑터)"다.
// 도메인 코어의 CredentialIssuer 아웃바운드 포트(README "서버 > 요청 처리"의 8단계)를
// HS256 JWT 발급으로 구현한다. 모든 검증을 통과한 신원에 서버 자체 접근 자격(JWT)을 만들어
// 돌려준다.
//
// 외부 JWT 라이브러리 없이 표준 라이브러리(crypto/hmac + crypto/sha256 + encoding/json +
// encoding/base64)로 직접 서명한다. 도메인 doc.go 의 표준 라이브러리 전용 원칙, STS 어댑터가
// AWS SDK 없이 구현한 관례와 맞춘다. HS256 은 대칭키라, 향후 /verify 엔드포인트가 같은
// 시크릿으로 서명을 재계산해 검증할 수 있도록 표준 JWT 형태(3 세그먼트, base64url no pad,
// HS256)로 맞춰 발급한다.
package issuer

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// headerSegment 는 {"alg":"HS256","typ":"JWT"} 를 base64url(no pad) 인코딩한 고정값이다.
// 헤더는 항상 같으므로 리터럴을 직접 인코딩해, 맵 마샬링의 필드 순서 비결정성을 피한다.
var headerSegment = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// claims 는 발급 JWT 의 페이로드다. 구조체 필드 선언 순서가 곧 JSON 직렬화 순서이므로,
// 같은 입력이면 항상 같은 바이트가 나온다(결정적 서명).
type claims struct {
	Iss     string `json:"iss"`
	Sub     string `json:"sub"`     // Identity.ARN. 허용 목록 대조 대상이자 안정적 주체 식별자.
	Aud     string `json:"aud"`
	Iat     int64  `json:"iat"`     // 발급 시각(Unix 초).
	Exp     int64  `json:"exp"`     // 만료 시각(Unix 초). exp = iat + TTL.
	Jti     string `json:"jti"`     // 토큰 고유 id. 추적/재전송 대비.
	Account string `json:"account"` // Identity.Account. 감사/로그용 부가 정보.
	UserID  string `json:"user_id"` // Identity.UserID. 감사/로그용 부가 정보.
}

// Issuer 는 HS256 JWT 로 서버 자체 접근 자격을 발급하는 CredentialIssuer 구현이다.
type Issuer struct {
	secret   []byte
	ttl      time.Duration
	issuer   string
	audience string

	// now 는 iat/exp 계산에 쓸 현재 시각 소스다. 테스트에서 시각을 고정하려고 필드로 둔다.
	// 도메인 Clock 포트는 코어의 신선도 판단용(4단계)이라 여기 재사용하지 않고, 어댑터 내부의
	// 인코딩 세부로 로컬에 가둔다(clock 어댑터가 time.Now 를 한 곳에 가둔 철학과 동일).
	now func() time.Time
}

// New 는 로드/검증된 Params 로 Issuer 를 만든다. 값의 권위 있는 검증은 Load 가 부팅 시점에
// 마쳤으므로(STS 어댑터 New 와 동일하게) 여기서는 에러를 반환하지 않는다. 주입 시크릿은
// 방어적으로 복사해 외부 변형으로부터 격리하고, now 는 time.Now 로 초기화한다.
func New(p Params) *Issuer {
	secret := append([]byte(nil), p.Secret...)
	return &Issuer{
		secret:   secret,
		ttl:      p.TTL,
		issuer:   p.Issuer,
		audience: p.Audience,
		now:      time.Now,
	}
}

// IssueCredential 은 검증된 신원에 HS256 JWT 를 발급한다. 발급 과정의 실패(난수/직렬화)는
// 도메인 거부가 아니라 인프라 실패이므로 일반 에러로 그대로 전파한다(코어 service.go 가
// issuer 에러를 거부로 바꾸지 않고 올린다).
func (i *Issuer) IssueCredential(_ context.Context, id domain.Identity) (domain.Credential, error) {
	now := i.now()
	exp := now.Add(i.ttl)

	jti, err := newJTI()
	if err != nil {
		return domain.Credential{}, fmt.Errorf("jti 생성 실패: %w", err)
	}

	payloadSeg, err := encodeSegment(claims{
		Iss:     i.issuer,
		Sub:     id.ARN,
		Aud:     i.audience,
		Iat:     now.Unix(),
		Exp:     exp.Unix(),
		Jti:     jti,
		Account: id.Account,
		UserID:  id.UserID,
	})
	if err != nil {
		return domain.Credential{}, fmt.Errorf("JWT 페이로드 직렬화 실패: %w", err)
	}

	signingInput := headerSegment + "." + payloadSeg
	token := signingInput + "." + i.sign(signingInput)

	// ExpiresAt 은 토큰 exp 클레임과 같은 초 단위로 맞춰, 반환값과 토큰이 어긋나지 않게 한다.
	return domain.Credential{Token: token, ExpiresAt: time.Unix(exp.Unix(), 0).UTC()}, nil
}

// encodeSegment 는 값을 JSON 마샬 후 base64url(no pad) 로 인코딩한다.
func encodeSegment(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sign 은 서명 입력(header.payload)에 시크릿으로 HMAC-SHA256 서명을 계산해 base64url(no pad)
// 로 돌려준다.
func (i *Issuer) sign(signingInput string) string {
	m := hmac.New(sha256.New, i.secret)
	m.Write([]byte(signingInput))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// newJTI 는 16바이트 난수를 base64url(no pad) 로 인코딩한 토큰 고유 id 를 만든다.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// 컴파일 타임에 Issuer 가 아웃바운드 포트를 만족하는지 확인한다.
var _ domain.CredentialIssuer = (*Issuer)(nil)
