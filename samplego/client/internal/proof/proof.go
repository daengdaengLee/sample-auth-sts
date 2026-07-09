// Package proof 는 README "클라이언트 > 증명 생성 및 전송"의 3~4단계(증명 형태 결정, SigV4
// 서명 + 서버 바인딩)를 구현한다. 보유한 AWS 자격증명으로 GetCallerIdentity 요청에 헤더 기반
// SigV4 서명을 만들고, 서버 바인딩 헤더를 서명 범위(SignedHeaders)에 포함한 뒤, 서버 /auth 가
// 받는 JSON 엔벨로프로 직렬화한다. 시크릿 키는 서명에만 쓰이고 요청/엔벨로프에는 담기지 않는다
// (PoP). 서명 자체는 검증된 구현(aws-sdk-go-v2 의 signer/v4)에 위임한다.
package proof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	// service 는 SigV4 서명에 쓰는 AWS 서비스 이름이다. GetCallerIdentity 는 STS 호출이다.
	service = "sts"

	// bindingHeader 는 서버 바인딩 값을 싣는 헤더 이름이다. 서버 수신 어댑터의 bindingHeader
	// (samplego/server/adapter/inbound/auth.go)와 반드시 같은 이름이어야 한다. 이 헤더는 서명
	// 전에 설정해 SignedHeaders 에 들어가야 의미가 있다(서명 범위 밖 첨부는 위변조로 무력화됨).
	bindingHeader = "X-Server-Binding"

	// contentTypeHeader, contentTypeForm 은 GetCallerIdentity POST 폼 본문의 콘텐츠 타입이다.
	contentTypeHeader = "Content-Type"
	contentTypeForm   = "application/x-www-form-urlencoded"

	// formBody 는 서명 대상 GetCallerIdentity 요청 본문이다. 서버는 이 바디에서 Action 이
	// 정확히 1개(GetCallerIdentity)인지 확인한다(전달 요청 형태 검증).
	formBody = "Action=GetCallerIdentity&Version=2011-06-15"
)

// Input 은 BuildProof 에 넘기는 서명 입력이다. 자격증명은 미리 획득해 넘기고(SDK 체인이든
// static 이든 호출부가 결정), 이 패키지는 서명과 직렬화만 맡는다.
type Input struct {
	// Credentials 는 SigV4 서명에 쓸 AWS 자격증명이다. 시크릿 키는 서명에만 쓰이고 밖으로
	// 나가지 않는다. 임시 자격증명이면 SessionToken 이 채워져 있고, signer 가 이를
	// X-Amz-Security-Token 헤더로 서명 범위에 넣는다.
	Credentials aws.Credentials

	// Endpoint 는 서명/위임 대상 STS 엔드포인트 URL 이다. 서버 allowlist 안의 https 여야 한다.
	Endpoint string

	// Region 은 SigV4 서명 리전이다. 엔드포인트와 일치해야 한다.
	Region string

	// BindingValue 는 서명 범위에 넣을 서버 바인딩 값이다. 서버 기대값과 일치해야 한다.
	BindingValue string

	// SignedAt 은 서명 시각(X-Amz-Date 의 근거)이다. 서버 신선도 검증(최대 age)을 통과하려면
	// 현재 시각에 가까워야 한다. 보통 time.Now() 를 넘긴다.
	SignedAt time.Time
}

// BuildProof 는 입력 자격증명으로 GetCallerIdentity 요청에 헤더 기반 SigV4 서명을 만들고,
// 서버 바인딩 헤더를 서명 범위에 포함한 엔벨로프를 돌려준다. 절차:
//
//  1. GetCallerIdentity POST 요청을 만들고 Content-Type 과 X-Server-Binding 을 서명 전에 설정
//     한다(서명 범위에 들어가도록).
//  2. 본문의 sha256 을 payload hash 로 계산한다(헤더 기반이라 UNSIGNED-PAYLOAD 가 아님).
//  3. signer.SignHTTP 로 Authorization 과 X-Amz-Date(및 임시 자격증명 시 X-Amz-Security-Token)
//     를 채운다. host 는 signer 가 항상 서명 범위에 넣는다.
//  4. 서명된 요청을 엔벨로프로 직렬화한다(Host 명시 추가, 본문 base64 표준 인코딩).
func BuildProof(ctx context.Context, in Input) (Envelope, error) {
	body := []byte(formBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Envelope{}, fmt.Errorf("GetCallerIdentity 요청 생성 실패: %w", err)
	}

	// 서명 전에 설정해야 서명 범위(SignedHeaders)에 포함된다. 바인딩 헤더는 특히 서명 범위
	// 안에 있어야만 혼동된 대리자 완화가 성립한다(서명 밖 첨부는 값이 바뀌어도 서명이 안 깨져
	// 무의미). signer 는 요청에 존재하는 헤더 전부를 서명하므로(무시 집합 제외), 여기서 설정한
	// 두 헤더가 자동으로 서명된다.
	req.Header.Set(contentTypeHeader, contentTypeForm)
	req.Header.Set(bindingHeader, in.BindingValue)

	// 헤더 기반 서명이라 payload hash 는 본문 바이트의 hex sha256 이다(빈 값/UNSIGNED-PAYLOAD
	// 아님). 한 바이트라도 어긋나면 STS 가 서명 재검증에서 거절한다.
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])

	// signer.SignHTTP 는 req 를 제자리에서 변형해 Authorization 과 X-Amz-Date 를 채운다
	// (X-Amz-Date 형식은 서버 amzDateFormat 과 같은 ISO8601 basic). 수동으로 X-Amz-Date 를
	// 넣으면 중복 키가 되어 서버가 거부하므로 넣지 않는다.
	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, in.Credentials, req, payloadHash, service, in.Region, in.SignedAt); err != nil {
		return Envelope{}, fmt.Errorf("SigV4 서명 실패: %w", err)
	}

	return envelopeFromRequest(req, in.Endpoint, body), nil
}
