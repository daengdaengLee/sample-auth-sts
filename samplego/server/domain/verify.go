package domain

import "context"

// VerifyTokenInput 은 토큰 검증 인바운드 포트로 넘기는 유스케이스 입력이다. 수신 어댑터가
// 요청에서 뽑은 발급 토큰 문자열을 그대로 담는다.
type VerifyTokenInput struct {
	Token string
}

// VerifyTokenOutput 은 검증이 성공했을 때의 결과다. 검증된 토큰의 클레임을 돌려줘,
// 수신 어댑터가 응답 본문으로 매핑하거나 감사에 쓸 수 있게 한다.
type VerifyTokenOutput struct {
	Claims VerifiedToken
}

// TokenVerifier 는 "서버가 발급한 토큰을 검증한다" 인바운드(구동) 포트다. 수신 어댑터가
// 토큰 문자열을 이 포트로 넘기면, 코어가 서명 검증(아웃바운드 위임)과 만료(exp)/발급자
// (iss)/대상(aud) 판단을 수행하고 통과 시 클레임을 돌려준다. Authenticator(/auth)와 짝을
// 이루는 /verify 유스케이스의 진입점이다. ctx 로 요청 범위 상관관계 속성(request_id 등)과
// 취소를 아웃바운드 포트까지 전달한다.
type TokenVerifier interface {
	VerifyToken(ctx context.Context, in VerifyTokenInput) (VerifyTokenOutput, error)
}
