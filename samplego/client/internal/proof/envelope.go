package proof

import (
	"encoding/base64"
	"net/http"
)

// presignedEnvelope 는 pre-signed URL 서명 결과를 엔벨로프로 직렬화한다. presigned 는 SigV4
// 정보(Algorithm/Credential/Date/Expires/SignedHeaders/Signature)와 Action/Version 이 모두 URL
// 쿼리에 실리므로, method 는 GET, url 은 쿼리를 포함한 서명된 URL, body 는 빈 값이다. 헤더로는
// 서명 범위에 든 X-Server-Binding(실제 값)과 Host(서명에 쓴 값)만 싣는다. 바인딩은 쿼리가 아니라
// 실제 헤더로 보내되 X-Amz-SignedHeaders 에 포함돼 있어야 하며(혼동된 대리자 완화), Host 는 서버
// STS 어댑터가 http.Request.Host 로 되옮겨 서명을 보존한다. body 는 base64 표준 인코딩 규약을
// 지켜 빈 문자열로 둔다(서버가 base64.StdEncoding 으로 디코드하면 빈 바이트).
func presignedEnvelope(signedURI, host, binding string) Envelope {
	return Envelope{
		Method: http.MethodGet,
		URL:    signedURI,
		Headers: map[string][]string{
			bindingHeader: {binding},
			"Host":        {host},
		},
		Body: "",
	}
}

// Envelope 는 클라이언트가 /auth 로 보내는 JSON 엔벨로프다. 서버 수신 어댑터의 authRequest
// (samplego/server/adapter/inbound/auth.go 의 authRequest)와 바이트 단위로 호환되도록 필드명/
// 타입/태그를 그대로 맞춘다. Body 는 서명 대상 바이트를 정확히 보존하려고 base64 표준 인코딩
// 으로 싣는다(서버가 base64.StdEncoding 으로 디코드).
type Envelope struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

// envelopeFromRequest 는 서명이 끝난 http.Request 를 엔벨로프로 직렬화한다. 서명 범위에 든
// 헤더(Authorization/X-Amz-Date/X-Server-Binding 등)를 변형 없이 옮기고, Go 가 Header 맵에
// 두지 않는 Host 를 서명에 쓴 값 그대로 명시 추가한다(서버 STS 어댑터가 headers["Host"] 를
// http.Request.Host 로 되옮겨 서명을 보존한다). endpoint 는 서명에 쓴 URL 문자열과 동일해야
// 하고, body 는 서명 대상 원본 바이트다.
func envelopeFromRequest(req *http.Request, endpoint string, body []byte) Envelope {
	headers := make(map[string][]string, len(req.Header)+1)
	for name, values := range req.Header {
		// 값 슬라이스를 복사해, 이후 req 변형이 엔벨로프에 새지 않게 한다.
		copied := make([]string, len(values))
		copy(copied, values)
		headers[name] = copied
	}

	// Host 는 http.Request.Header 가 아니라 http.Request.Host 에 있다. 서명은 host 헤더를
	// 서명 범위에 넣으므로, 서명에 쓴 host 값을 그대로 엔벨로프에 담아야 STS 재검증이 깨지지
	// 않는다. Host 필드가 비면 URL 의 host 가 서명에 쓰였으므로 그것을 쓴다.
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers["Host"] = []string{host}

	return Envelope{
		Method:  req.Method,
		URL:     endpoint,
		Headers: headers,
		Body:    base64.StdEncoding.EncodeToString(body),
	}
}
