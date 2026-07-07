package domain

import (
	"context"
	"time"
)

// IdentityVerifier 는 STS 위임의 추상(신원 검증 아웃바운드 포트)이다. 보존된 원본 서명
// 요청을 그대로 넘기면 호출자 신원(ARN 등)을 돌려받는다(5~6단계). 위임 대상 엔드포인트가
// 허용 목록의 진짜 STS 인지(5단계 STS 엔드포인트 신뢰)는 이 포트를 구현하는 어댑터가
// 경계에서 강제하며, 코어는 관여하지 않는다.
type IdentityVerifier interface {
	VerifyIdentity(ctx context.Context, req PreservedRequest) (Identity, error)
}

// CredentialIssuer 는 검증된 신원에 서버 자체 접근 자격을 발급하는 아웃바운드 포트다(8단계).
type CredentialIssuer interface {
	IssueCredential(ctx context.Context, id Identity) (Credential, error)
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
