package domain

import "context"

// VerifyService 는 인바운드 포트 TokenVerifier 의 구현으로, 서버가 발급한 토큰의 검증
// 논리를 오케스트레이션한다. 서명 검증(아웃바운드 위임)은 TokenInspector 에 맡기고, 만료
// (exp)와 발급자(iss)/대상(aud) 판단은 코어에서 수행한다. Service(/auth)와 대칭 구조다.
type VerifyService struct {
	clock     Clock
	inspector TokenInspector

	// policy 는 iss/aud 기대값을 주는 검증 정책 포트다. Service(/auth)가 판단값을 Policy
	// 포트로 읽는 것과 대칭으로, 검증 기대값도 포트 뒤에 둔다(테스트 대역 주입 용이).
	policy VerifyPolicy
}

// NewVerifyService 는 시계/검사기와 검증 정책 포트를 주입해 VerifyService 를 만든다.
func NewVerifyService(clock Clock, inspector TokenInspector, policy VerifyPolicy) *VerifyService {
	return &VerifyService{
		clock:     clock,
		inspector: inspector,
		policy:    policy,
	}
}

// VerifyToken 은 토큰 한 건에 대해 서명(위임) -> 만료 -> 발급자/대상 순으로 판단하고, 모두
// 통과하면 클레임을 돌려준다. 서명/구조 실패는 검사기가 *VerificationRejected 로 돌려주므로
// 그대로 전파하고, 만료/발급자/대상 불일치는 로컬 판단이므로 *RejectionError 로 반환한다.
func (s *VerifyService) VerifyToken(ctx context.Context, in VerifyTokenInput) (VerifyTokenOutput, error) {
	// 서명/구조 검증은 아웃바운드 검사기에 위임한다. 무효 토큰(*VerificationRejected)이나
	// 내부 실패(일반 에러)를 구분 없이 그대로 전파해, 수신 어댑터가 도메인 타입으로 가른다.
	vt, err := s.inspector.Inspect(ctx, in.Token)
	if err != nil {
		return VerifyTokenOutput{}, err
	}

	// 만료 검사: 현재 시각이 exp 이상이면(exp 를 지났으면) 만료다. exp 는 초 단위라 발급의
	// 초 단위 절삭과 대칭으로 판단한다.
	if !s.clock.Now().Before(vt.ExpiresAt) {
		return VerifyTokenOutput{}, reject(ReasonTokenExpired, "토큰이 만료됨(exp 경과)")
	}

	// 발급자/대상 검사: 이 서버가 발급한 토큰인지(iss)와 이 서버의 대상으로 발급됐는지(aud)를
	// 확인해, 다른 발급자/대상의 토큰을 받아들이지 않는다.
	if vt.Issuer != s.policy.ExpectedIssuer() {
		return VerifyTokenOutput{}, reject(ReasonIssuerMismatch, "토큰 iss 클레임이 발급자 기대값과 일치하지 않음")
	}
	if vt.Audience != s.policy.ExpectedAudience() {
		return VerifyTokenOutput{}, reject(ReasonAudienceMismatch, "토큰 aud 클레임이 대상 기대값과 일치하지 않음")
	}

	return VerifyTokenOutput{Claims: vt}, nil
}

// 컴파일 타임에 VerifyService 가 인바운드 포트를 만족하는지 확인한다.
var _ TokenVerifier = (*VerifyService)(nil)
