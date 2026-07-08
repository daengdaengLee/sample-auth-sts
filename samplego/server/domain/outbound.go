package domain

import (
	"context"
	"time"
)

// IdentityVerifier 는 STS 위임의 추상(신원 검증 아웃바운드 포트)이다. 보존된 원본 서명
// 요청을 그대로 넘기면 호출자 신원(ARN 등)을 돌려받는다(5~6단계). 위임 대상 엔드포인트가
// 허용 목록의 진짜 STS 인지(5단계 STS 엔드포인트 신뢰)는 이 포트를 구현하는 어댑터가
// 경계에서 강제하며, 코어는 관여하지 않는다.
//
// 에러 계약: 무자격(클라이언트측 거절, 예: 서명 무효/만료)은 *VerificationRejected 로(감싸서라도)
// 반환하고, 전송 실패/5xx/파싱 불가 같은 인프라 실패는 일반 에러로 반환한다. 코어는 이 에러를
// 그대로 전파하므로, 수신 어댑터가 이 도메인 타입만으로 무자격(4xx) 대 인프라(5xx)를 가른다.
type IdentityVerifier interface {
	VerifyIdentity(ctx context.Context, req PreservedRequest) (Identity, error)
}

// CredentialIssuer 는 검증된 신원에 서버 자체 접근 자격을 발급하는 아웃바운드 포트다(8단계).
type CredentialIssuer interface {
	IssueCredential(ctx context.Context, id Identity) (Credential, error)
}

// VerifiedToken 은 서명 검증을 통과한 토큰에서 뽑아낸 클레임이다. 코어는 이 값으로 만료
// (ExpiresAt)와 발급자(Issuer)/대상(Audience)을 판단한다. 시각 클레임은 초 단위 Unix 시각을
// time.Time 으로 되살린 값이다(발급이 초 단위로 자르는 것과 대칭).
type VerifiedToken struct {
	Issuer    string
	Subject   string
	Audience  string
	ExpiresAt time.Time
	IssuedAt  time.Time
	JTI       string
	Account   string
	UserID    string
}

// TokenInspector 는 서버가 발급한 토큰의 서명/구조를 검증하는 아웃바운드 포트다(/verify).
// 발급과 같은 대칭키를 쥔 어댑터가 HS256 서명을 재계산해 상수시간 비교하고, 구조(세그먼트
// 수/헤더 alg)를 확인한 뒤 클레임을 돌려준다. 서명이 유효한지까지만 책임지며, 만료/발급자/
// 대상 같은 정책 판단은 코어(TokenVerifier 구현)가 한다(신원 검증 어댑터가 STS 위임만 맡고
// 허용 ARN 판단은 코어가 하는 것과 대칭).
//
// 에러 계약: 무효 토큰(구조/서명/헤더 alg 불일치 등 클라이언트측 거절)은 *VerificationRejected
// 로(감싸서라도) 반환하고, 내부 실패는 일반 에러로 반환한다. 코어는 이 에러를 그대로
// 전파하므로, 수신 어댑터가 이 도메인 타입만으로 무효(401) 대 인프라(5xx)를 가른다.
type TokenInspector interface {
	Inspect(ctx context.Context, token string) (VerifiedToken, error)
}

// Clock 은 신선도 판단에 쓸 현재 시각을 제공하는 아웃바운드 포트다(4단계). 테스트에서
// 시각을 고정할 수 있도록 포트로 둔다.
type Clock interface {
	Now() time.Time
}

// Policy 는 코어가 판단에 쓰는 정책/설정 값을 제공하는 아웃바운드 포트다. 코어가 실제로
// 읽는 값만 노출한다. STS 엔드포인트 허용 목록은 코어가 쓰지 않고 신원 검증 어댑터가
// 경계에서 강제하므로 여기 두지 않는다(인터페이스 분리).
type Policy interface {
	// ExpectedBinding 은 이 서버만 받아들이는 고유 바인딩 기대값이다(2단계).
	ExpectedBinding() string

	// MaxAge 는 받아들일 서명 요청의 최대 age 다(4단계).
	MaxAge() time.Duration

	// IsAllowedARN 은 STS 가 돌려준 ARN 이 허용 신원 목록에 드는지 판단한다(7단계).
	IsAllowedARN(arn string) bool
}
