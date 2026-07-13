package proof

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// testInput 은 결정적 서명을 위한 기준 입력을 만든다. static 자격증명과 고정 시각을 써, 서명은
// 실 AWS 없이도 만들어지고 X-Amz-Date 가 고정된다.
func testInput() Input {
	return Input{
		Credentials: aws.Credentials{
			AccessKeyID:     "AKIDEXAMPLE",
			SecretAccessKey: "secretexamplekey",
		},
		Endpoint:     "https://sts.amazonaws.com",
		Region:       "us-east-1",
		BindingValue: "https://server.example/audience",
		SignedAt:     time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
	}
}

// signedHeaderSet 은 서버 수신 어댑터와 같은 방식으로 Authorization 값에서 SignedHeaders 를
// 소문자 집합으로 뽑는다(테스트 검증용 사본). 서버가 실제로 파싱하는 대상과 같은 형식을 본다.
func signedHeaderSet(authorization string) map[string]bool {
	const marker = "SignedHeaders="
	i := strings.Index(authorization, marker)
	if i < 0 {
		return nil
	}
	rest := authorization[i+len(marker):]
	if j := strings.IndexByte(rest, ','); j >= 0 {
		rest = rest[:j]
	}
	set := make(map[string]bool)
	for _, name := range strings.Split(rest, ";") {
		if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
			set[n] = true
		}
	}
	return set
}

// TestBuildProof_signedHeaders 는 서명 범위(SignedHeaders)에 서버가 요구하는 host, x-amz-date,
// x-server-binding 이 모두 들어가는지 확인한다. 이 세 헤더가 서명 범위 밖이면 서버가 거부한다.
func TestBuildProof_signedHeaders(t *testing.T) {
	env, err := BuildProof(context.Background(), testInput())
	if err != nil {
		t.Fatalf("BuildProof 실패: %v", err)
	}

	authz := env.Headers["Authorization"]
	if len(authz) != 1 {
		t.Fatalf("Authorization 헤더 값 개수 = %d, want 1", len(authz))
	}
	signed := signedHeaderSet(authz[0])
	for _, want := range []string{"host", "x-amz-date", "x-server-binding"} {
		if !signed[want] {
			t.Errorf("SignedHeaders 에 %q 가 없음: %q", want, authz[0])
		}
	}
}

// TestBuildProof_envelopeShape 는 엔벨로프가 서버 와이어 계약과 맞는지 확인한다: method=POST,
// url=엔드포인트, 보안 헤더가 정확히 1개 값, X-Amz-Date 형식, Host 존재, body 가 표준 base64 로
// GetCallerIdentity 폼으로 디코드.
func TestBuildProof_envelopeShape(t *testing.T) {
	in := testInput()
	env, err := BuildProof(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildProof 실패: %v", err)
	}

	if env.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", env.Method)
	}
	if env.URL != in.Endpoint {
		t.Errorf("URL = %q, want %q", env.URL, in.Endpoint)
	}

	// 보안 관련 헤더는 정확히 1개 값이어야 한다(서버가 다중 값을 거부).
	for _, name := range []string{"Authorization", "X-Amz-Date", "X-Server-Binding", "Host"} {
		if got := len(env.Headers[name]); got != 1 {
			t.Errorf("%s 헤더 값 개수 = %d, want 1", name, got)
		}
	}

	// X-Amz-Date 는 서명 시각에서 온 ISO8601 basic 이어야 한다(서버 amzDateFormat 과 동일).
	const amzDateFormat = "20060102T150405Z"
	rawDate := env.Headers["X-Amz-Date"][0]
	parsed, err := time.Parse(amzDateFormat, rawDate)
	if err != nil {
		t.Fatalf("X-Amz-Date 형식 파싱 실패(%q): %v", rawDate, err)
	}
	if !parsed.Equal(in.SignedAt) {
		t.Errorf("X-Amz-Date = %v, want %v", parsed, in.SignedAt)
	}

	// X-Server-Binding 값이 입력과 같아야 한다.
	if got := env.Headers["X-Server-Binding"][0]; got != in.BindingValue {
		t.Errorf("X-Server-Binding = %q, want %q", got, in.BindingValue)
	}

	// body 는 표준 base64 로 GetCallerIdentity 폼으로 디코드돼야 한다.
	decoded, err := base64.StdEncoding.DecodeString(env.Body)
	if err != nil {
		t.Fatalf("body base64 표준 디코드 실패: %v", err)
	}
	if string(decoded) != formBody {
		t.Errorf("body = %q, want %q", string(decoded), formBody)
	}
}

// TestBuildProof_sessionTokenSigned 는 임시 자격증명(세션 토큰 포함)일 때 X-Amz-Security-Token
// 이 헤더와 서명 범위에 함께 들어가는지 확인한다(누락 시 STS 가 거절).
func TestBuildProof_sessionTokenSigned(t *testing.T) {
	in := testInput()
	in.Credentials.SessionToken = "session-token-example"

	env, err := BuildProof(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildProof 실패: %v", err)
	}

	if got := len(env.Headers["X-Amz-Security-Token"]); got != 1 {
		t.Fatalf("X-Amz-Security-Token 헤더 값 개수 = %d, want 1", got)
	}
	if got := env.Headers["X-Amz-Security-Token"][0]; got != in.Credentials.SessionToken {
		t.Errorf("X-Amz-Security-Token = %q, want %q", got, in.Credentials.SessionToken)
	}
	signed := signedHeaderSet(env.Headers["Authorization"][0])
	if !signed["x-amz-security-token"] {
		t.Error("SignedHeaders 에 x-amz-security-token 이 없음")
	}
}

// TestBuildProof_forwardable 은 엔벨로프를 서버 STS 어댑터와 같은 방식으로 재구성해(Host 를
// req.Host 로 옮기고 body 를 그대로 실어) 목 STS 로 보낼 수 있음을 확인한다. 목 STS 가 받은
// 메서드/바디/바인딩 헤더/Host 를 검사해, 위임 전달이 충실히 이뤄짐을 보인다.
func TestBuildProof_forwardable(t *testing.T) {
	env, err := BuildProof(context.Background(), testInput())
	if err != nil {
		t.Fatalf("BuildProof 실패: %v", err)
	}

	type captured struct {
		method  string
		body    string
		binding string
		host    string
	}
	got := make(chan captured, 1)

	// STS 허용 목록은 https 만 받으므로 목 STS 는 TLS 서버여야 한다(서버 normalizeEndpoint 와
	// 일치). 목은 서명을 검증하지 않고 받은 요청만 캡처한다.
	stsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- captured{method: r.Method, body: string(b), binding: r.Header.Get("X-Server-Binding"), host: r.Host}
		_, _ = io.WriteString(w, "ok")
	}))
	defer stsSrv.Close()

	// 서버 STS 어댑터 buildRequest 와 같은 재구성: 원본 method/body 로 요청을 만들고, 헤더를
	// 그대로 옮기되 Host 는 req.Host 로 옮긴다. 목 STS URL 로 대상만 바꿔 전달 가능성만 본다.
	decoded, err := base64.StdEncoding.DecodeString(env.Body)
	if err != nil {
		t.Fatalf("body 디코드 실패: %v", err)
	}
	req, err := http.NewRequest(env.Method, stsSrv.URL, strings.NewReader(string(decoded)))
	if err != nil {
		t.Fatalf("전달 요청 생성 실패: %v", err)
	}
	for name, values := range env.Headers {
		if strings.EqualFold(name, "Host") {
			if len(values) > 0 {
				req.Host = values[0]
			}
			continue
		}
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	resp, err := stsSrv.Client().Do(req)
	if err != nil {
		t.Fatalf("목 STS 전달 실패: %v", err)
	}
	defer resp.Body.Close()

	select {
	case c := <-got:
		if c.method != http.MethodPost {
			t.Errorf("전달된 메서드 = %q, want POST", c.method)
		}
		if c.body != formBody {
			t.Errorf("전달된 바디 = %q, want %q", c.body, formBody)
		}
		if c.binding != "https://server.example/audience" {
			t.Errorf("전달된 X-Server-Binding = %q", c.binding)
		}
		// Host 는 서명에 쓴 원본 STS 호스트여야 한다(엔벨로프가 보존).
		if c.host != "sts.amazonaws.com" {
			t.Errorf("전달된 Host = %q, want sts.amazonaws.com", c.host)
		}
	default:
		t.Error("목 STS 가 요청을 받지 못함")
	}
}

// presignInput 은 결정적 presigned 서명을 위한 기준 입력을 만든다(만료 90s 지정).
func presignInput() Input {
	in := testInput()
	in.Expiry = 90 * time.Second
	return in
}

// TestBuildPresignedProof_envelopeShape 는 presigned 엔벨로프가 서버 와이어 계약과 맞는지
// 확인한다: method=GET, url 쿼리에 SigV4 정보(Algorithm/Credential/Date/Expires/SignedHeaders/
// Signature)와 Action/Version 이 실리고, body 는 빈 값, 헤더에는 X-Server-Binding 과 Host 만 있다.
func TestBuildPresignedProof_envelopeShape(t *testing.T) {
	in := presignInput()
	env, err := BuildPresignedProof(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildPresignedProof 실패: %v", err)
	}

	if env.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", env.Method)
	}
	if env.Body != "" {
		t.Errorf("Body = %q, want 빈 값", env.Body)
	}

	u, err := url.Parse(env.URL)
	if err != nil {
		t.Fatalf("URL 파싱 실패(%q): %v", env.URL, err)
	}
	q := u.Query()
	for _, name := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature", "Action", "Version"} {
		if len(q[name]) != 1 {
			t.Errorf("쿼리 %s 값 개수 = %d, want 1 (url=%s)", name, len(q[name]), env.URL)
		}
	}
	if got := q.Get("Action"); got != "GetCallerIdentity" {
		t.Errorf("Action = %q, want GetCallerIdentity", got)
	}
	// X-Amz-Expires 는 입력 만료의 초 단위여야 한다.
	if got := q.Get("X-Amz-Expires"); got != "90" {
		t.Errorf("X-Amz-Expires = %q, want 90", got)
	}
	// X-Amz-Date 는 서명 시각에서 온 ISO8601 basic 이어야 한다.
	const amzDateFormat = "20060102T150405Z"
	parsed, err := time.Parse(amzDateFormat, q.Get("X-Amz-Date"))
	if err != nil {
		t.Fatalf("X-Amz-Date 형식 파싱 실패(%q): %v", q.Get("X-Amz-Date"), err)
	}
	if !parsed.Equal(in.SignedAt) {
		t.Errorf("X-Amz-Date = %v, want %v", parsed, in.SignedAt)
	}

	// 보안 관련 헤더는 정확히 1개 값이어야 한다. presigned 는 인증 정보를 쿼리에 싣고, 헤더로는
	// 서명 범위에 든 X-Server-Binding 과 Host 만 보낸다(Authorization 헤더는 없어야 한다).
	for _, name := range []string{"X-Server-Binding", "Host"} {
		if got := len(env.Headers[name]); got != 1 {
			t.Errorf("%s 헤더 값 개수 = %d, want 1", name, got)
		}
	}
	if got := len(env.Headers["Authorization"]); got != 0 {
		t.Errorf("presigned 인데 Authorization 헤더가 있음(개수=%d)", got)
	}
	if got := env.Headers["X-Server-Binding"][0]; got != in.BindingValue {
		t.Errorf("X-Server-Binding = %q, want %q", got, in.BindingValue)
	}
}

// TestBuildPresignedProof_bindingSigned 는 서버 바인딩 헤더가 X-Amz-SignedHeaders(서명 범위)
// 안에 드는지 확인한다. 서명 범위 밖이면 전달 과정에서 값이 바뀌어도 서명이 깨지지 않아 혼동된
// 대리자 완화가 무력화되므로, 반드시 host 와 함께 서명 범위에 있어야 한다.
func TestBuildPresignedProof_bindingSigned(t *testing.T) {
	env, err := BuildPresignedProof(context.Background(), presignInput())
	if err != nil {
		t.Fatalf("BuildPresignedProof 실패: %v", err)
	}

	u, err := url.Parse(env.URL)
	if err != nil {
		t.Fatalf("URL 파싱 실패: %v", err)
	}
	signed := parseSignedHeaderList(u.Query().Get("X-Amz-SignedHeaders"))
	for _, want := range []string{"host", "x-server-binding"} {
		if !signed[want] {
			t.Errorf("X-Amz-SignedHeaders 에 %q 가 없음: %q", want, u.Query().Get("X-Amz-SignedHeaders"))
		}
	}
}

// TestBuildPresignedProof_sessionTokenHoisted 는 임시 자격증명(세션 토큰 포함)일 때 세션 토큰이
// X-Amz-Security-Token 쿼리 파라미터로 실리는지 확인한다(presigned 는 헤더가 아니라 쿼리로
// hoisting; 누락 시 STS 가 거절).
func TestBuildPresignedProof_sessionTokenHoisted(t *testing.T) {
	in := presignInput()
	in.Credentials.SessionToken = "session-token-example"

	env, err := BuildPresignedProof(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildPresignedProof 실패: %v", err)
	}

	u, err := url.Parse(env.URL)
	if err != nil {
		t.Fatalf("URL 파싱 실패: %v", err)
	}
	if got := u.Query().Get("X-Amz-Security-Token"); got != in.Credentials.SessionToken {
		t.Errorf("X-Amz-Security-Token(쿼리) = %q, want %q", got, in.Credentials.SessionToken)
	}
	// 세션 토큰은 헤더가 아니라 쿼리로 실려야 한다.
	if got := len(env.Headers["X-Amz-Security-Token"]); got != 0 {
		t.Errorf("presigned 인데 X-Amz-Security-Token 이 헤더로 실림(개수=%d)", got)
	}
}

// parseSignedHeaderList 는 세미콜론으로 구분된 SignedHeaders 목록을 소문자 집합으로 뽑는다
// (서버 수신 어댑터와 같은 방식의 테스트용 사본). presigned 는 X-Amz-SignedHeaders 쿼리에 이
// 형식으로 서명 범위를 싣는다.
func parseSignedHeaderList(list string) map[string]bool {
	set := make(map[string]bool)
	for _, name := range strings.Split(list, ";") {
		if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
			set[n] = true
		}
	}
	return set
}
