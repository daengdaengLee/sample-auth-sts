package domain

import "context"

// AuthenticateInput 은 인바운드 포트로 넘기는 유스케이스 입력이다.
type AuthenticateInput struct {
	Request SignedRequest
}

// AuthenticateOutput 은 유스케이스가 성공했을 때의 결과다. 발급된 자격과 함께, 로그/감사에
// 쓸 수 있도록 검증된 신원도 돌려준다.
type AuthenticateOutput struct {
	Credential Credential
	Identity   Identity
}

// Authenticator 는 "인증 요청을 처리한다" 인바운드(구동) 포트다. 수신 어댑터가 서명된
// 요청을 파싱해 이 포트를 호출하면, 코어가 바인딩/형태/신선도/허용 신원을 판단하고 자격
// 발급 여부를 결정한다. ctx 로 요청 범위 상관관계 속성(request_id 등)과 취소를 아웃바운드
// 포트까지 전달한다.
type Authenticator interface {
	Authenticate(ctx context.Context, in AuthenticateInput) (AuthenticateOutput, error)
}
