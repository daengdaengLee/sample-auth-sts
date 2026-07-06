package domain

import (
	"context"
	"time"
)

// fakePolicy 는 Policy 포트의 테스트 대역이다. 각 검증을 개별적으로 통과/실패시키도록
// 값을 직접 지정한다.
type fakePolicy struct {
	binding string
	maxAge  time.Duration
	allowed map[string]bool
}

func (p fakePolicy) ExpectedBinding() string      { return p.binding }
func (p fakePolicy) MaxAge() time.Duration        { return p.maxAge }
func (p fakePolicy) IsAllowedARN(arn string) bool { return p.allowed[arn] }

// fakeClock 은 Clock 포트의 테스트 대역으로, 고정 시각을 돌려준다.
type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time { return c.now }

// fakeVerifier 는 IdentityVerifier 포트의 테스트 대역이다. 호출 여부와 받은 원본 요청을
// 기록해, 단락(호출 안 됨)과 전달 충실도를 검증할 수 있게 한다.
type fakeVerifier struct {
	id     Identity
	err    error
	called bool
	gotReq PreservedRequest
}

func (v *fakeVerifier) VerifyIdentity(_ context.Context, req PreservedRequest) (Identity, error) {
	v.called = true
	v.gotReq = req
	return v.id, v.err
}

// fakeIssuer 는 CredentialIssuer 포트의 테스트 대역이다. 호출 여부와 받은 신원을 기록한다.
type fakeIssuer struct {
	cred   Credential
	err    error
	called bool
	gotID  Identity
}

func (i *fakeIssuer) IssueCredential(_ context.Context, id Identity) (Credential, error) {
	i.called = true
	i.gotID = id
	return i.cred, i.err
}
