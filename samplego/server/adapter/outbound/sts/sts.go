// Package sts 는 README 헥사고날 설계의 "STS 신원 검증 어댑터(아웃바운드 어댑터)"다.
// 도메인 코어의 IdentityVerifier 아웃바운드 포트를 실제 AWS STS 위임으로 구현한다
// (README "서버 > 요청 처리"의 5~6단계). 코어가 보존해 넘긴 원본 서명 요청을 재구성
// 없이 그대로 STS 로 전달하고, 돌려받은 GetCallerIdentity 응답에서 호출자 신원(ARN 등)을
// 뽑아 코어로 돌려준다.
//
// 위임 대상이 허용 목록의 진짜 STS 엔드포인트인지 강제하는 5단계(STS 엔드포인트 신뢰)는
// 이 어댑터가 경계에서 책임진다. STS 엔드포인트 허용 목록을 Policy 포트가 아니라 여기에
// 두는 것은 인터페이스 분리에 따른 것이다(domain/outbound.go, adapter/outbound/config
// 주석 참고). 코어는 관여하지 않는다.
//
// 표준 라이브러리만 쓴다(AWS SDK 도입 없음). SigV4 서명은 STS 가 검증하며, 이 어댑터는
// 서명을 해석하지 않고 서명된 요청을 바이트 그대로 중개한다.
package sts

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// hostHeader 는 재구성 시 http.Request.Host 필드로 옮겨 실어야 하는 헤더 이름이다.
// SigV4 서명은 Host 헤더를 서명 범위에 넣으므로, Header 맵에만 두면 net/http 가
// 전송 시 이를 덮어써 서명이 깨질 수 있다.
const hostHeader = "Host"

// VerificationError 는 STS 가 호출자 신원을 확인해 주지 못했음을(또는 위임 자체를
// 거절했음을) 나타낸다. 서명 무효/만료 같은 STS 의 클라이언트측 거절(4xx)과 위임
// 대상이 허용 목록의 진짜 STS 엔드포인트가 아닌 경우가 여기 해당한다. 무자격 응답으로
// 매핑되어야 하는 "검증 실패"이며, 전송 실패/STS 5xx/응답 파싱 불가 같은 인프라 실패와
// 구분된다(그쪽은 이 타입이 아닌 일반 에러로 전파된다).
//
// 도메인 코어(service.go)는 verifier 에러를 거부가 아니라 그대로 전파하므로, 이후
// 수신 어댑터가 이 타입 여부로 무자격(4xx) 대 인프라 실패(5xx)를 갈라 응답 상태를
// 정한다. domain.RejectionError 와 같은 역할을 어댑터 경계에서 맡되, 새 도메인
// RejectionReason 을 늘리지 않고 어댑터 계층에 가둔다.
type VerificationError struct {
	// Reason 은 검증이 실패한 이유의 짧은 식별자다(로그/디버깅용).
	Reason string

	// HTTPStatus 는 STS 응답 상태코드다. 엔드포인트 허용 목록 위반처럼 STS 호출 전에
	// 걸린 경우 0 이다.
	HTTPStatus int

	// STSCode, STSMessage 는 STS ErrorResponse 에서 파싱한 값이다(있을 때만).
	STSCode    string
	STSMessage string
}

// Error 는 error 인터페이스를 만족시킨다.
func (e *VerificationError) Error() string {
	var b strings.Builder
	b.WriteString("STS 신원 검증 실패(")
	b.WriteString(e.Reason)
	b.WriteString(")")
	if e.HTTPStatus != 0 {
		fmt.Fprintf(&b, " status=%d", e.HTTPStatus)
	}
	if e.STSCode != "" {
		fmt.Fprintf(&b, " code=%s", e.STSCode)
	}
	if e.STSMessage != "" {
		fmt.Fprintf(&b, " message=%s", e.STSMessage)
	}
	return b.String()
}

// AsVerificationError 는 err 가(감싸져 있더라도) *VerificationError 인지 검사해 돌려준다.
// 수신 어댑터가 무자격 응답(검증 실패)과 인프라 실패를 구분하는 데 쓴다.
// domain.AsRejection 과 짝을 이룬다.
func AsVerificationError(err error) (*VerificationError, bool) {
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}

// getCallerIdentityResponse 는 STS GetCallerIdentity 성공 응답(XML)의 관심 필드다.
// 네임스페이스는 무시하고 로컬 이름으로만 매칭한다.
type getCallerIdentityResponse struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Result  struct {
		Arn     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
}

// stsErrorResponse 는 STS 에러 응답(XML)의 관심 필드다.
type stsErrorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// Verifier 는 허용된 STS 엔드포인트로 원본 서명 요청을 위임해 호출자 신원을 돌려받는
// IdentityVerifier 구현이다.
type Verifier struct {
	client  *http.Client
	allowed map[string]bool
}

// New 는 HTTP 클라이언트와 허용할 STS 엔드포인트 목록을 주입해 Verifier 를 만든다.
// 엔드포인트는 scheme+host 기준으로 정규화해 보관하며(경로/쿼리는 무시), 위임 대상
// URL 의 엔드포인트가 이 집합에 들 때만 전달한다. 목록이 비면 아무 엔드포인트도
// 허용하지 않는다(전부 거부). 타임아웃 등 전송 정책은 주입한 client 가 정한다.
func New(client *http.Client, allowedEndpoints []string) *Verifier {
	allowed := make(map[string]bool)
	for _, ep := range allowedEndpoints {
		if key := normalizeEndpoint(ep); key != "" {
			allowed[key] = true
		}
	}
	return &Verifier{client: client, allowed: allowed}
}

// VerifyIdentity 는 보존된 원본 서명 요청을 허용된 STS 엔드포인트로 그대로 전달하고,
// 돌려받은 GetCallerIdentity 응답에서 호출자 신원을 뽑아 반환한다. 위임 대상이 허용
// 목록에 없거나 STS 가 요청을 거절하면 *VerificationError 를, 전송/파싱 같은 인프라
// 실패는 일반 에러를 반환한다.
func (v *Verifier) VerifyIdentity(ctx context.Context, req domain.PreservedRequest) (domain.Identity, error) {
	// 5단계. STS 엔드포인트 신뢰: 위임 대상 엔드포인트가 허용 목록에 든 진짜 STS 인지
	// 강제한다. 어긋나면 HTTP 호출 없이 즉시 거부해, 가짜 엔드포인트로의 전달을 막는다.
	endpoint := normalizeEndpoint(req.URL)
	if endpoint == "" {
		return domain.Identity{}, &VerificationError{Reason: "위임 대상 URL 을 해석할 수 없음"}
	}
	if !v.allowed[endpoint] {
		return domain.Identity{}, &VerificationError{Reason: "위임 대상이 STS 엔드포인트 허용 목록에 없음"}
	}

	httpReq, err := buildRequest(ctx, req)
	if err != nil {
		return domain.Identity{}, fmt.Errorf("STS 요청 재구성 실패: %w", err)
	}

	// 6단계. STS 위임: 서명된 요청을 바이트 그대로 전달한다. 전송 실패는 인프라 실패다.
	resp, err := v.client.Do(httpReq)
	if err != nil {
		return domain.Identity{}, fmt.Errorf("STS 위임 요청 전송 실패: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return domain.Identity{}, fmt.Errorf("STS 응답 본문 읽기 실패: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return domain.Identity{}, classifyErrorResponse(resp.StatusCode, body)
	}

	var parsed getCallerIdentityResponse
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return domain.Identity{}, fmt.Errorf("STS 응답 XML 파싱 실패: %w", err)
	}
	if parsed.Result.Arn == "" {
		return domain.Identity{}, fmt.Errorf("STS 응답에 ARN 이 없음")
	}

	return domain.Identity{
		ARN:     parsed.Result.Arn,
		Account: parsed.Result.Account,
		UserID:  parsed.Result.UserID,
	}, nil
}

// buildRequest 는 보존된 원본 요청을 net/http 요청으로 재구성한다. SigV4 서명을 깨지
// 않도록 헤더를 변형 없이 그대로 옮기고, Host 헤더는 http.Request.Host 필드로 옮겨 싣는다.
func buildRequest(ctx context.Context, req domain.PreservedRequest) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}

	for name, values := range req.Header {
		if strings.EqualFold(name, hostHeader) {
			if len(values) > 0 {
				httpReq.Host = values[0]
			}
			continue
		}
		for _, val := range values {
			httpReq.Header.Add(name, val)
		}
	}

	return httpReq, nil
}

// classifyErrorResponse 는 STS 비200 응답을 검증 실패(4xx, 클라이언트측 거절)와 인프라
// 실패(그 외, 예: 5xx)로 가른다. ErrorResponse XML 이 있으면 코드/메시지를 담는다.
func classifyErrorResponse(status int, body []byte) error {
	var parsed stsErrorResponse
	_ = xml.Unmarshal(body, &parsed) // 파싱 실패해도 상태코드로는 분류할 수 있으므로 무시한다.

	if status >= 400 && status < 500 {
		return &VerificationError{
			Reason:     "STS 가 서명된 요청을 거절함",
			HTTPStatus: status,
			STSCode:    parsed.Error.Code,
			STSMessage: parsed.Error.Message,
		}
	}

	if parsed.Error.Code != "" {
		return fmt.Errorf("STS 위임 실패(status=%d code=%s): %s", status, parsed.Error.Code, parsed.Error.Message)
	}
	return fmt.Errorf("STS 위임 실패(status=%d)", status)
}

// normalizeEndpoint 는 URL 문자열에서 비교용 엔드포인트 키(scheme + "://" + 소문자 host)를
// 뽑는다. 경로/쿼리는 무시한다. scheme 또는 host 가 없으면 빈 문자열을 돌려준다(무효).
func normalizeEndpoint(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// 컴파일 타임에 Verifier 가 아웃바운드 포트를 만족하는지 확인한다.
var _ domain.IdentityVerifier = (*Verifier)(nil)
