package sts

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// successBody 는 STS GetCallerIdentity 성공 응답(XML) 샘플이다. 네임스페이스가 있어도
// 로컬 이름으로 파싱되는지 함께 확인한다.
const successBody = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:role/workload</Arn>
    <UserId>AROAEXAMPLEID:session</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>`

// errorBody 는 STS 에러 응답(XML) 샘플이다(서명 무효 등).
const errorBody = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidClientTokenId</Code>
    <Message>The security token included in the request is invalid.</Message>
  </Error>
  <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
</ErrorResponse>`

// throttleBody 는 STS 스로틀링 에러 응답(XML) 샘플이다. HTTP 400 으로 오지만 서명이
// 무효한 게 아니라 일시 상태다.
const throttleBody = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>Throttling</Code>
    <Message>Rate exceeded</Message>
  </Error>
  <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
</ErrorResponse>`

// preservedFor 는 주어진 대상 URL 로 향하는 GetCallerIdentity 원본 요청 대역을 만든다.
func preservedFor(target string) domain.PreservedRequest {
	return domain.PreservedRequest{
		Method: http.MethodPost,
		URL:    target,
		Header: map[string][]string{
			"Content-Type":     {"application/x-www-form-urlencoded; charset=utf-8"},
			"X-Amz-Date":       {"20240101T000000Z"},
			"Authorization":    {"AWS4-HMAC-SHA256 Credential=EXAMPLE/20240101/us-east-1/sts/aws4_request"},
			"X-Server-Binding": {"https://server.example/audience"},
			"Host":             {"sts.amazonaws.com"},
		},
		Body: []byte("Action=GetCallerIdentity&Version=2011-06-15"),
	}
}

// TestVerifyIdentity_success 는 정상 응답에서 ARN/Account/UserID 가 정확히 파싱되는지
// 확인한다. https 만 허용하므로 TLS 테스트 서버를 쓴다.
func TestVerifyIdentity_success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		io.WriteString(w, successBody)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	id, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err != nil {
		t.Fatalf("VerifyIdentity() 에러: %v", err)
	}

	want := domain.Identity{
		ARN:     "arn:aws:iam::123456789012:role/workload",
		Account: "123456789012",
		UserID:  "AROAEXAMPLEID:session",
	}
	if id != want {
		t.Errorf("Identity=%+v, want %+v", id, want)
	}
}

// TestVerifyIdentity_forwardsOriginal 은 보존된 원본 요청이 재구성 없이 그대로 STS 에
// 도달하는지(메서드/경로/쿼리/헤더/바디, 특히 Host 헤더와 서명 헤더 보존) 확인한다.
func TestVerifyIdentity_forwardsOriginal(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotAuth, gotBinding, gotHost string
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		gotBinding = r.Header.Get("X-Server-Binding")
		gotHost = r.Host
		gotBody, _ = io.ReadAll(r.Body)
		io.WriteString(w, successBody)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})
	// 경로/쿼리가 그대로 전달되는지 보려고 대상 URL 에 둘 다 실어 보낸다. 허용 목록
	// 대조는 scheme+host+port 기준이라 경로가 있어도 매칭된다.
	req := preservedFor(srv.URL + "/some/path?Foo=bar&Baz=qux")

	if _, err := v.VerifyIdentity(context.Background(), req); err != nil {
		t.Fatalf("VerifyIdentity() 에러: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method=%q, want POST", gotMethod)
	}
	if gotPath != "/some/path" {
		t.Errorf("path=%q, want /some/path (경로가 보존되지 않음)", gotPath)
	}
	if gotQuery != "Foo=bar&Baz=qux" {
		t.Errorf("query=%q, want Foo=bar&Baz=qux (쿼리가 보존되지 않음)", gotQuery)
	}
	if gotAuth != req.Header["Authorization"][0] {
		t.Errorf("Authorization 헤더가 보존되지 않음: %q", gotAuth)
	}
	if gotBinding != req.Header["X-Server-Binding"][0] {
		t.Errorf("X-Server-Binding 헤더가 보존되지 않음: %q", gotBinding)
	}
	if gotHost != "sts.amazonaws.com" {
		t.Errorf("Host=%q, want sts.amazonaws.com (Host 헤더가 요청 Host 로 실리지 않음)", gotHost)
	}
	if !reflect.DeepEqual(gotBody, req.Body) {
		t.Errorf("body=%q, want %q", gotBody, req.Body)
	}
}

// TestVerifyIdentity_endpointNotAllowed 는 위임 대상이 허용 목록에 없으면 HTTP 호출
// 없이 검증 실패 에러를 반환하는지 확인한다.
func TestVerifyIdentity_endpointNotAllowed(t *testing.T) {
	var hit bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		io.WriteString(w, successBody)
	}))
	defer srv.Close()

	// 허용 목록에는 진짜 STS 만 두고, 위임 대상은 가짜(테스트 서버)로 준다.
	v := New(srv.Client(), []string{"https://sts.amazonaws.com"})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("허용 목록 밖 엔드포인트인데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); !ok {
		t.Errorf("검증 실패 타입이 아님: %v", err)
	}
	if hit {
		t.Error("허용 목록 위반인데 STS 로 요청이 나갔음")
	}
}

// TestVerifyIdentity_stsRejects 는 STS 가 4xx(서명 무효)로 응답하면 검증 실패 타입
// 에러로 구분되고 코드/메시지가 담기는지 확인한다.
func TestVerifyIdentity_stsRejects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, errorBody)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("STS 가 거절했는데 에러가 나지 않음")
	}
	ve, ok := asVerificationError(err)
	if !ok {
		t.Fatalf("검증 실패 타입이 아님: %v", err)
	}
	if ve.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus=%d, want 403", ve.HTTPStatus)
	}
	if ve.STSCode != "InvalidClientTokenId" {
		t.Errorf("STSCode=%q, want InvalidClientTokenId", ve.STSCode)
	}
	if !strings.Contains(ve.STSMessage, "invalid") {
		t.Errorf("STSMessage 에 STS 메시지가 담기지 않음: %q", ve.STSMessage)
	}
}

// TestVerifyIdentity_throttlingIsInfra 는 STS 스로틀링(HTTP 400 Throttling)이 영구
// 무자격이 아니라 재시도 대상 인프라 실패로 분류되는지 확인한다.
func TestVerifyIdentity_throttlingIsInfra(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, throttleBody)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("스로틀링인데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); ok {
		t.Errorf("스로틀링(400 Throttling)이 무자격으로 잘못 분류됨: %v", err)
	}
}

// TestVerifyIdentity_tooManyRequestsIsInfra 는 HTTP 429 가 코드와 무관하게 인프라
// 실패로 분류되는지 확인한다.
func TestVerifyIdentity_tooManyRequestsIsInfra(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("429 인데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); ok {
		t.Errorf("429 가 무자격으로 잘못 분류됨: %v", err)
	}
}

// TestVerifyIdentity_stsServerError 는 STS 5xx 는 검증 실패가 아니라 인프라 실패로
// 전파되는지 확인한다(무자격이 아니라 재시도 대상).
func TestVerifyIdentity_stsServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("STS 5xx 인데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); ok {
		t.Errorf("STS 5xx 가 검증 실패로 잘못 분류됨: %v", err)
	}
}

// TestVerifyIdentity_redirectNotFollowed 는 STS 가 3xx 를 줘도 리다이렉트를 따라가지
// 않고(가짜 후속 호스트로 서명 요청이 새지 않고) 인프라 오류를 반환하는지 확인한다.
func TestVerifyIdentity_redirectNotFollowed(t *testing.T) {
	var finalHit bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/final":
			// 리다이렉트를 따라갔다면 여기로 와서 200 성공이 된다.
			finalHit = true
			io.WriteString(w, successBody)
		default:
			http.Redirect(w, r, "/final", http.StatusFound)
		}
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL+"/redirect"))
	if err == nil {
		t.Fatal("리다이렉트 응답인데 에러가 나지 않음(따라간 것으로 보임)")
	}
	if _, ok := asVerificationError(err); ok {
		t.Errorf("리다이렉트가 무자격으로 잘못 분류됨: %v", err)
	}
	if finalHit {
		t.Error("리다이렉트를 따라가 검사받지 않은 경로로 요청이 나갔음")
	}
}

// TestVerifyIdentity_transportError 는 전송 실패(닫힌 서버)가 인프라 실패로 전파되는지
// 확인한다.
func TestVerifyIdentity_transportError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target := srv.URL
	client := srv.Client()
	srv.Close() // 서버를 닫아 전송이 실패하게 만든다.

	v := New(client, []string{target})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(target))
	if err == nil {
		t.Fatal("전송이 실패해야 하는데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); ok {
		t.Errorf("전송 실패가 검증 실패로 잘못 분류됨: %v", err)
	}
}

// TestVerifyIdentity_unparsableSuccess 는 200 이지만 XML 이 깨졌으면 인프라 실패로
// 전파되는지 확인한다.
func TestVerifyIdentity_unparsableSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "not xml at all")
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("파싱 불가 응답인데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); ok {
		t.Errorf("파싱 실패가 검증 실패로 잘못 분류됨: %v", err)
	}
}

// TestVerifyIdentity_oversizeBody 는 응답 본문이 상한을 넘으면 인프라 오류로 전파되는지
// 확인한다(메모리 고갈 방지).
func TestVerifyIdentity_oversizeBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("a", maxResponseBytes+1))
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("상한 초과 본문인데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); ok {
		t.Errorf("상한 초과가 무자격으로 잘못 분류됨: %v", err)
	}
}

// TestVerifyIdentity_oversizeRejectionKeepsStatus 는 상한 초과 검사가 상태 분류보다
// 뒤에 오도록 재정렬된 동작을 고정한다. 큰 본문(>상한)을 가진 4xx 무자격 응답은 상한
// 오류(인프라)가 아니라 상태 기반 VerificationError(HTTPStatus 보존)로 분류돼야 한다.
func TestVerifyIdentity_oversizeRejectionKeepsStatus(t *testing.T) {
	body := errorBody + strings.Repeat("a", maxResponseBytes) // 상한 초과, 상태는 403
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, body)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("초과 본문 4xx 인데 에러가 나지 않음")
	}
	ve, ok := asVerificationError(err)
	if !ok {
		t.Fatalf("초과 본문 4xx 가 상태 기반 무자격으로 분류되지 않음(상한 오류로 새어나감?): %v", err)
	}
	if ve.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus=%d, want 403 (상태 분류가 상한 검사보다 먼저여야 함)", ve.HTTPStatus)
	}
	// 절단된 본문에서도 앞쪽 ErrorResponse 는 파싱되므로 Code 가 담겨야 한다.
	if ve.STSCode != "InvalidClientTokenId" {
		t.Errorf("STSCode=%q, want InvalidClientTokenId (절단 본문에서 Code 파싱 실패?)", ve.STSCode)
	}
}

// TestVerifyIdentity_exactMaxBody 는 정확히 상한 크기인 본문은 거부되지 않고 정상
// 파싱되는지 확인한다(경계 off-by-one: len > max 이어야 하며 >= 이면 안 됨). 성공 XML
// 뒤를 공백으로 채워 정확히 maxResponseBytes 로 맞춘다(뒤 공백은 파싱에 무해).
func TestVerifyIdentity_exactMaxBody(t *testing.T) {
	pad := maxResponseBytes - len(successBody)
	if pad < 0 {
		t.Fatalf("successBody 가 상한보다 큼: %d", len(successBody))
	}
	body := successBody + strings.Repeat(" ", pad)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	id, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err != nil {
		t.Fatalf("정확히 상한 크기 본문인데 에러: %v", err)
	}
	if id.ARN != "arn:aws:iam::123456789012:role/workload" {
		t.Errorf("ARN=%q, 정상 파싱되지 않음", id.ARN)
	}
}

// TestVerifyIdentity_invalidTargetURL 은 위임 대상 URL 이 무효면 HTTP 호출 없이 검증
// 실패로 거부되는지 확인한다.
func TestVerifyIdentity_invalidTargetURL(t *testing.T) {
	v := New(http.DefaultClient, []string{"https://sts.amazonaws.com"})

	req := preservedFor("://missing-scheme")
	_, err := v.VerifyIdentity(context.Background(), req)
	if err == nil {
		t.Fatal("무효 URL 인데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); !ok {
		t.Errorf("무효 URL 이 검증 실패로 분류되지 않음: %v", err)
	}
}

// TestVerifyIdentity_httpTargetRejected 는 http(비 https) 대상은 허용 목록 등록/매칭이
// 안 돼 HTTP 호출 없이 거부되는지 확인한다(평문 다운그레이드 방지).
func TestVerifyIdentity_httpTargetRejected(t *testing.T) {
	// 허용 목록도 http 로 주지만 normalizeEndpoint 가 무효로 처리해 빈 집합이 된다.
	v := New(http.DefaultClient, []string{"http://sts.amazonaws.com"})

	_, err := v.VerifyIdentity(context.Background(), preservedFor("http://sts.amazonaws.com/"))
	if err == nil {
		t.Fatal("http 대상인데 에러가 나지 않음")
	}
	if _, ok := asVerificationError(err); !ok {
		t.Errorf("http 대상이 검증 실패로 거부되지 않음: %v", err)
	}
}

// TestNormalizeEndpoint 는 정규화가 scheme(https 만)/host(소문자, 후행점 제거)/포트(기본
// 443 보충)를 일관되게 처리해, 표기가 달라도 같은 엔드포인트가 같은 키로 매칭되는지
// 확인한다.
func TestNormalizeEndpoint(t *testing.T) {
	want := "https://sts.example:443"
	same := []string{
		"https://sts.example",
		"https://sts.example:443",
		"https://sts.example.",
		"HTTPS://STS.EXAMPLE",
		"  https://sts.example/some/path?q=1  ",
	}
	for _, raw := range same {
		if got := normalizeEndpoint(raw); got != want {
			t.Errorf("normalizeEndpoint(%q)=%q, want %q", raw, got, want)
		}
	}

	invalid := []string{
		"",
		"http://sts.example", // https 아님
		"://missing-scheme",  // scheme 없음
		"sts.example:443",    // scheme 없음(host 로 해석 안 됨)
		"https:///only-path", // host 없음
		"ftp://sts.example",  // https 아님
	}
	for _, raw := range invalid {
		if got := normalizeEndpoint(raw); got != "" {
			t.Errorf("normalizeEndpoint(%q)=%q, want \"\"(무효)", raw, got)
		}
	}

	// IPv6 host 는 대괄호를 보존한 유효한 키로 정규화되고, 포트 생략/명시가 같은 키로
	// 매칭된다.
	wantV6 := "https://[::1]:443"
	for _, raw := range []string{"https://[::1]", "https://[::1]:443", "HTTPS://[::1]"} {
		if got := normalizeEndpoint(raw); got != wantV6 {
			t.Errorf("normalizeEndpoint(%q)=%q, want %q", raw, got, wantV6)
		}
	}
}

// TestIsTransientCode 는 스로틀/레이트리밋 계열 코드는 일시(재시도)로, 서명/자격 관련
// 거절 코드는 일시가 아님으로 분류되는지 확인한다. 정확일치가 아니라 부분문자열이라
// 목록에 없는 새 스로틀 코드도 일시로 강등되는지 함께 본다.
func TestIsTransientCode(t *testing.T) {
	transient := []string{
		"Throttling",
		"ThrottlingException",
		"ThrottledException",
		"RequestThrottled",
		"RequestThrottledException",
		"TooManyRequestsException",
		"RequestLimitExceeded",
		"BandwidthLimitExceeded",
		"LimitExceededException",
		"throttling", // 대소문자 무시
	}
	for _, c := range transient {
		if !isTransientCode(c) {
			t.Errorf("isTransientCode(%q)=false, want true(일시)", c)
		}
	}

	// 영구(무자격) 코드는 false 여야 한다. 특히 매칭 토큰의 부분을 품은 비스로틀
	// 코드(예: "...Exceeded" 지만 "limitexceeded" 아님)가 일시로 과매칭되지 않는지
	// 확인해, 정확일치 맵과 구별되는 Contains 휴리스틱의 경계를 방어한다.
	permanent := []string{
		"",
		"InvalidClientTokenId",
		"SignatureDoesNotMatch",
		"ExpiredToken",
		"AccessDenied",
		"ValidationError",
		"MalformedPolicyDocument",
		"PackedPolicyTooLarge",
		"WidgetCountExceeded", // "exceeded" 는 품지만 "limitexceeded" 아님 -> 무자격 유지
	}
	for _, c := range permanent {
		if isTransientCode(c) {
			t.Errorf("isTransientCode(%q)=true, want false(무자격)", c)
		}
	}
}

// TestNew_endpointNormalization 은 허용 목록 항목이 정규화되어, 경로/대소문자/공백/포트
// 표기 차이가 있어도 같은 엔드포인트로 매칭되는지 통합 수준에서 확인한다.
func TestNew_endpointNormalization(t *testing.T) {
	var hit bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		io.WriteString(w, successBody)
	}))
	defer srv.Close()

	// 허용 목록은 앞뒤 공백과 경로를 붙여 주고, 위임 대상 URL 은 경로가 있는 형태로 준다.
	v := New(srv.Client(), []string{"  " + srv.URL + "/some/path  "})

	if _, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL+"/")); err != nil {
		t.Fatalf("정규화된 엔드포인트 매칭 실패: %v", err)
	}
	if !hit {
		t.Error("정규화 후에도 허용된 엔드포인트로 요청이 나가지 않음")
	}
}

// TestAsVerificationError_wrapped 는 asVerificationError 가 감싼 에러도 풀어내는지
// (errors.As 경유) 최소 sanity 를 본다.
func TestAsVerificationError_wrapped(t *testing.T) {
	base := &VerificationError{Reason: "테스트"}
	wrapped := errors.Join(errors.New("바깥"), base)
	if _, ok := asVerificationError(wrapped); !ok {
		t.Error("감싼 VerificationError 를 풀어내지 못함")
	}
}

// TestVerificationError_unwrapsToDomain 은 VerificationError 가 도메인 무자격 에러
// (*domain.VerificationRejected)로 풀리는지 확인한다. 이 브리지 덕분에 수신 어댑터가 STS
// 어댑터에 의존하지 않고 domain.AsVerificationRejected 로 무자격을 분류할 수 있다.
func TestVerificationError_unwrapsToDomain(t *testing.T) {
	base := &VerificationError{Reason: "서명 무효", HTTPStatus: 403}

	vr, ok := domain.AsVerificationRejected(base)
	if !ok {
		t.Fatal("VerificationError 가 domain.VerificationRejected 로 풀리지 않음")
	}
	if vr.Reason != "서명 무효" {
		t.Errorf("Reason = %q, want 서명 무효", vr.Reason)
	}

	// 감싼 경우에도 풀려야 한다.
	if _, ok := domain.AsVerificationRejected(errors.Join(errors.New("바깥"), base)); !ok {
		t.Error("감싼 VerificationError 를 domain 무자격으로 풀어내지 못함")
	}

	// 일반 인프라 에러는 무자격으로 분류되면 안 된다.
	if _, ok := domain.AsVerificationRejected(errors.New("전송 실패")); ok {
		t.Error("일반 에러가 무자격으로 잘못 분류됨")
	}
}
