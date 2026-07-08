package domain

import "errors"

// RejectionReason 은 로컬 검증 단계에서 요청을 거부한 사유를 식별한다. 수신 어댑터는
// 이 값을 로그에 남기고 무자격 응답으로 매핑한다.
type RejectionReason string

const (
	// ReasonBindingMismatch 는 서버 바인딩 헤더 값이 기대값과 다를 때다(2단계, 혼동된 대리자).
	ReasonBindingMismatch RejectionReason = "binding_mismatch"

	// ReasonInvalidShape 는 전달 요청이 GetCallerIdentity 호출이 아닐 때다(3단계, 전달 요청 검증).
	ReasonInvalidShape RejectionReason = "invalid_shape"

	// ReasonStale 은 요청이 허용된 최대 age 를 벗어났거나 미래 시각일 때다(4단계, 재전송).
	ReasonStale RejectionReason = "stale"

	// ReasonARNNotAllowed 는 STS 가 돌려준 ARN 이 허용 신원 목록에 없을 때다(7단계, 반환 신원 검증).
	ReasonARNNotAllowed RejectionReason = "arn_not_allowed"
)

// RejectionError 는 코어의 로컬 검증이 요청을 거부했음을 나타내는 에러다. Reason 으로
// 어느 검증에서 걸렸는지 구분한다. 아웃바운드 포트(STS/발급)의 인프라 실패는 이 타입이
// 아니라 원래 에러 그대로 전파되므로, 어댑터는 둘을 구분해 응답 상태를 정할 수 있다.
type RejectionError struct {
	Reason  RejectionReason
	Message string
}

// Error 는 error 인터페이스를 만족시킨다.
func (e *RejectionError) Error() string {
	return "요청 거부(" + string(e.Reason) + "): " + e.Message
}

// reject 는 RejectionError 를 만드는 내부 헬퍼다.
func reject(reason RejectionReason, msg string) *RejectionError {
	return &RejectionError{Reason: reason, Message: msg}
}

// AsRejection 은 err 가(감싸져 있더라도) *RejectionError 인지 검사해 돌려준다. 수신
// 어댑터가 거부(무자격 응답)와 인프라 실패(5xx)를 구분하는 데 쓴다.
func AsRejection(err error) (*RejectionError, bool) {
	var re *RejectionError
	if errors.As(err, &re) {
		return re, true
	}
	return nil, false
}

// VerificationRejected 는 신원 검증 포트(IdentityVerifier)가 "무자격"(클라이언트측 거절)을
// 나타낼 때 쓰는 도메인 에러다. 코어는 verifier 에러를 그대로 전파하므로, 수신 어댑터는 이
// 타입 여부로 무자격 응답과 인프라 실패를 가른다. 아웃바운드 어댑터(STS 등)는 이 타입을
// (감싸서라도) 반환해, 수신 어댑터가 특정 어댑터 패키지에 의존하지 않고 도메인 타입만으로
// 분류하게 한다. domain.RejectionError(로컬 검증 거부)와 짝을 이루되, 그쪽은 코어의 로컬
// 판단이고 이쪽은 위임 검증 결과다.
type VerificationRejected struct {
	// Reason 은 검증이 거절된 이유의 짧은 식별자다(로그/디버깅용).
	Reason string
}

// Error 는 error 인터페이스를 만족시킨다.
func (e *VerificationRejected) Error() string {
	return "신원 검증 거절: " + e.Reason
}

// AsVerificationRejected 는 err 가(감싸져 있더라도) *VerificationRejected 인지 검사해 돌려준다.
// 수신 어댑터가 무자격 응답과 인프라 실패를 구분하는 데 쓴다.
func AsVerificationRejected(err error) (*VerificationRejected, bool) {
	var ve *VerificationRejected
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
