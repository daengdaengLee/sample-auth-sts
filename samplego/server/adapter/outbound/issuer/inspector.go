package issuer

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// Inspector 는 서버가 발급한 HS256 JWT 의 서명/구조를 검증하는 TokenInspector 구현이다.
// 발급(Issuer)과 같은 패키지에 두어 대칭키(secret), 고정 헤더(headerSegment), 서명 계산
// (signWith), 클레임 구조(claims)를 그대로 재사용한다. 이렇게 발급/검증이 같은 소재를 쓰므로
// 형식이 어긋날 여지가 없다.
type Inspector struct {
	secret []byte
}

// NewInspector 는 로드/검증된 Params 로 Inspector 를 만든다. 값 검증은 Load 가 부팅 시점에
// 마쳤으므로 여기서는 에러를 반환하지 않는다. 주입 시크릿은 방어적으로 복사해 외부 변형으로
// 부터 격리한다(New 와 동일).
func NewInspector(p Params) *Inspector {
	return &Inspector{secret: append([]byte(nil), p.Secret...)}
}

// Inspect 는 토큰의 3 세그먼트 구조, 헤더(alg=HS256/typ=JWT), HS256 서명을 검증하고 클레임을
// 돌려준다. 무효 토큰(구조/헤더/서명 불일치, 세그먼트 base64/JSON 파싱 실패)은 도메인 계약에
// 따라 *domain.VerificationRejected 로 반환한다(수신 어댑터가 401 로 매핑). 만료/발급자/대상
// 판단은 여기서 하지 않고 코어(VerifyService)가 맡는다.
func (i *Inspector) Inspect(_ context.Context, token string) (domain.VerifiedToken, error) {
	// 정확히 3 세그먼트(header.payload.signature)여야 한다. 잘린 토큰/세그먼트 수 오류를 거른다.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return domain.VerifiedToken{}, &domain.VerificationRejected{Reason: "토큰 세그먼트 수가 3이 아님"}
	}

	// 헤더 세그먼트는 발급 고정값과 정확히 일치해야 한다. 이 한 번의 비교로 alg=HS256 과
	// typ=JWT 를 강제해, alg 변조(예: none/RS256 시도)를 원천 차단한다.
	if parts[0] != headerSegment {
		return domain.VerifiedToken{}, &domain.VerificationRejected{Reason: "헤더가 HS256/JWT 고정값과 일치하지 않음"}
	}

	// 서명 재계산 후 상수시간 비교. 같은 시크릿/알고리즘으로 header.payload 서명을 다시 만들어
	// 토큰의 서명 세그먼트와 hmac.Equal 로 비교한다(타이밍 공격 완화). base64 인코딩 형태로
	// 비교하므로, 서명 세그먼트가 잘못된 base64 이거나 길이가 달라도 불일치로 거부된다.
	signingInput := parts[0] + "." + parts[1]
	expectedSig := signWith(i.secret, signingInput)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return domain.VerifiedToken{}, &domain.VerificationRejected{Reason: "서명이 일치하지 않음"}
	}

	// 페이로드를 디코드해 클레임으로 되살린다. 서명이 검증됐어도 형식 불량은 무효로 본다.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return domain.VerifiedToken{}, &domain.VerificationRejected{Reason: "페이로드 base64url 디코드 실패"}
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return domain.VerifiedToken{}, &domain.VerificationRejected{Reason: "페이로드 JSON 파싱 실패"}
	}

	// 시각 클레임은 초 단위 Unix 시각을 UTC time.Time 으로 되살린다(발급의 초 단위 절삭과 대칭).
	return domain.VerifiedToken{
		Issuer:    c.Iss,
		Subject:   c.Sub,
		Audience:  c.Aud,
		ExpiresAt: time.Unix(c.Exp, 0).UTC(),
		IssuedAt:  time.Unix(c.Iat, 0).UTC(),
		JTI:       c.Jti,
		Account:   c.Account,
		UserID:    c.UserID,
	}, nil
}

// 컴파일 타임에 Inspector 가 아웃바운드 포트를 만족하는지 확인한다.
var _ domain.TokenInspector = (*Inspector)(nil)

// verifyPolicy 는 발급 설정(jwt 섹션)의 iss/aud 기대값을 코어에 노출하는 VerifyPolicy
// 구현이다. 발급 설정을 쥔 이 패키지에 두어, 발급과 검증이 같은 iss/aud 소스를 쓰게 한다.
type verifyPolicy struct {
	issuer   string
	audience string
}

// NewVerifyPolicy 는 로드/검증된 Params 의 Issuer/Audience 로 VerifyPolicy 를 만든다.
func NewVerifyPolicy(p Params) domain.VerifyPolicy {
	return verifyPolicy{issuer: p.Issuer, audience: p.Audience}
}

func (p verifyPolicy) ExpectedIssuer() string   { return p.issuer }
func (p verifyPolicy) ExpectedAudience() string { return p.audience }

// 컴파일 타임에 verifyPolicy 가 아웃바운드 포트를 만족하는지 확인한다.
var _ domain.VerifyPolicy = verifyPolicy{}
