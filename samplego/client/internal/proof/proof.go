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
	"net/url"
	"strconv"
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

	// actionKey, versionKey 는 presigned GET 요청 쿼리 파라미터의 이름이고, actionValue,
	// versionValue 는 그 값이다. 헤더 기반이 formBody 로 싣는 것과 같은 Action/Version 을
	// presigned 에서는 URL 쿼리로 싣는다. 서버는 쿼리에서 Action 을 뽑아 GetCallerIdentity 인지
	// 확인한다. 이름도 상수로 두어 값 상수와 대칭을 맞춘다(규약 변경 시 누락 방지).
	actionKey    = "Action"
	versionKey   = "Version"
	actionValue  = "GetCallerIdentity"
	versionValue = "2011-06-15"

	// amzExpiresParam 은 presigned 만료를 싣는 쿼리 파라미터 이름이다. presign 전에 이 값을
	// 쿼리에 넣어야 canonical 쿼리 문자열(서명 범위)에 포함된다. AWS SDK 의 PresignHTTP 는
	// 만료를 자동으로 넣지 않으므로 호출부가 직접 설정해야 한다.
	amzExpiresParam = "X-Amz-Expires"
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

	// Expiry 는 presigned 형태에서 X-Amz-Expires 로 실을 만료(서명 시각 기준 유효 구간 길이)다.
	// BuildProof(헤더 기반)는 쓰지 않고 BuildPresignedProof 만 쓴다. 양수여야 의미가 있다.
	Expiry time.Duration
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

// BuildPresignedProof 는 입력 자격증명으로 GET GetCallerIdentity 요청에 pre-signed URL(SigV4
// 쿼리) 서명을 만들고, 서버 바인딩 헤더를 서명 범위에 포함한 엔벨로프를 돌려준다(AWS IAM
// Authenticator 방식). 헤더 기반 BuildProof 와 달리 SigV4 정보와 Action/Version 이 URL 쿼리에
// 실리고, 만료를 클라이언트가 X-Amz-Expires 로 직접 지정한다. 절차:
//
//  1. Action/Version 과 X-Amz-Expires 를 쿼리에 넣은 GET 요청을 만든다. X-Amz-Expires 는 presign
//     전에 넣어야 canonical 쿼리 문자열(서명 범위)에 포함된다.
//  2. X-Server-Binding 을 presign 전에 헤더로 설정한다. 이 헤더는 X-Amz- 접두가 아니라 쿼리로
//     hoisting 되지 않고 서명된 canonical 헤더로 남아 X-Amz-SignedHeaders 에 들어간다(혼동된 대리자
//     완화가 성립하려면 반드시 서명 범위 안이어야 한다). 실제 헤더 값도 엔벨로프에 함께 실어 보낸다.
//  3. 빈 본문(GET)의 payload hash 로 signer.PresignHTTP 를 호출해 서명된 URL 을 얻는다.
//  4. 서명된 URL(쿼리 포함)과 바인딩/Host 헤더로 엔벨로프를 직렬화한다(본문은 빈 값).
func BuildPresignedProof(ctx context.Context, in Input) (Envelope, error) {
	u, err := url.Parse(in.Endpoint)
	if err != nil {
		return Envelope{}, fmt.Errorf("STS 엔드포인트 파싱 실패(%q): %w", in.Endpoint, err)
	}

	// Action/Version 과 만료를 쿼리에 넣는다. X-Amz-Expires 는 초 단위 정수이며, presign 전에
	// 넣어야 서명 범위(canonical 쿼리)에 포함돼 위변조가 서명을 깨뜨린다.
	q := u.Query()
	q.Set(actionKey, actionValue)
	q.Set(versionKey, versionValue)
	q.Set(amzExpiresParam, strconv.FormatInt(int64(in.Expiry/time.Second), 10))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Envelope{}, fmt.Errorf("GetCallerIdentity presigned 요청 생성 실패: %w", err)
	}

	// 서명 전에 설정해야 서명 범위(X-Amz-SignedHeaders)에 포함된다. X-Server-Binding 은 X-Amz-
	// 접두가 아니라 쿼리로 hoisting 되지 않고 서명된 canonical 헤더로 남는다.
	req.Header.Set(bindingHeader, in.BindingValue)

	// GET 은 본문이 없으므로 빈 바이트의 hex sha256 을 payload hash 로 쓴다(빈 문자열 해시).
	sum := sha256.Sum256(nil)
	payloadHash := hex.EncodeToString(sum[:])

	// PresignHTTP 는 req 를 변형하지 않고, 서명된 URL(쿼리에 SigV4 정보 포함)을 돌려준다. 임시
	// 자격증명이면 X-Amz-Security-Token 도 쿼리로 hoisting 된다(X-Amz- 접두라 hoisting 대상).
	signer := v4.NewSigner()
	signedURI, _, err := signer.PresignHTTP(ctx, in.Credentials, req, payloadHash, service, in.Region, in.SignedAt)
	if err != nil {
		return Envelope{}, fmt.Errorf("SigV4 presigned 서명 실패: %w", err)
	}

	return presignedEnvelope(signedURI, req.URL.Host, in.BindingValue), nil
}
