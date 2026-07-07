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
// 확인한다.
func TestVerifyIdentity_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
// 도달하는지(메서드/경로/헤더/바디, 특히 Host 헤더와 서명 헤더 보존) 확인한다.
func TestVerifyIdentity_forwardsOriginal(t *testing.T) {
	var gotMethod, gotAuth, gotBinding, gotHost string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotBinding = r.Header.Get("X-Server-Binding")
		gotHost = r.Host
		gotBody, _ = io.ReadAll(r.Body)
		io.WriteString(w, successBody)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})
	req := preservedFor(srv.URL)

	if _, err := v.VerifyIdentity(context.Background(), req); err != nil {
		t.Fatalf("VerifyIdentity() 에러: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method=%q, want POST", gotMethod)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if _, ok := AsVerificationError(err); !ok {
		t.Errorf("검증 실패 타입이 아님: %v", err)
	}
	if hit {
		t.Error("허용 목록 위반인데 STS 로 요청이 나갔음")
	}
}

// TestVerifyIdentity_stsRejects 는 STS 가 4xx(서명 무효)로 응답하면 검증 실패 타입
// 에러로 구분되고 코드/메시지가 담기는지 확인한다.
func TestVerifyIdentity_stsRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	ve, ok := AsVerificationError(err)
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

// TestVerifyIdentity_stsServerError 는 STS 5xx 는 검증 실패가 아니라 인프라 실패로
// 전파되는지 확인한다(무자격이 아니라 재시도 대상).
func TestVerifyIdentity_stsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("STS 5xx 인데 에러가 나지 않음")
	}
	if _, ok := AsVerificationError(err); ok {
		t.Errorf("STS 5xx 가 검증 실패로 잘못 분류됨: %v", err)
	}
}

// TestVerifyIdentity_transportError 는 전송 실패(닫힌 서버)가 인프라 실패로 전파되는지
// 확인한다.
func TestVerifyIdentity_transportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target := srv.URL
	client := srv.Client()
	srv.Close() // 서버를 닫아 전송이 실패하게 만든다.

	v := New(client, []string{target})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(target))
	if err == nil {
		t.Fatal("전송이 실패해야 하는데 에러가 나지 않음")
	}
	if _, ok := AsVerificationError(err); ok {
		t.Errorf("전송 실패가 검증 실패로 잘못 분류됨: %v", err)
	}
}

// TestVerifyIdentity_unparsableSuccess 는 200 이지만 XML 이 깨졌으면 인프라 실패로
// 전파되는지 확인한다.
func TestVerifyIdentity_unparsableSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "not xml at all")
	}))
	defer srv.Close()

	v := New(srv.Client(), []string{srv.URL})

	_, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL))
	if err == nil {
		t.Fatal("파싱 불가 응답인데 에러가 나지 않음")
	}
	if _, ok := AsVerificationError(err); ok {
		t.Errorf("파싱 실패가 검증 실패로 잘못 분류됨: %v", err)
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
	if _, ok := AsVerificationError(err); !ok {
		t.Errorf("무효 URL 이 검증 실패로 분류되지 않음: %v", err)
	}
}

// TestNew_endpointNormalization 은 허용 목록 항목이 scheme+host 기준으로 정규화되어,
// 경로/대소문자/공백 차이가 있어도 같은 엔드포인트로 매칭되는지 확인한다.
func TestNew_endpointNormalization(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		io.WriteString(w, successBody)
	}))
	defer srv.Close()

	// 허용 목록은 뒤에 공백/경로를 붙이고, 위임 대상 URL 은 경로가 있는 형태로 준다.
	v := New(srv.Client(), []string{"  " + srv.URL + "/some/path  "})

	if _, err := v.VerifyIdentity(context.Background(), preservedFor(srv.URL+"/")); err != nil {
		t.Fatalf("정규화된 엔드포인트 매칭 실패: %v", err)
	}
	if !hit {
		t.Error("정규화 후에도 허용된 엔드포인트로 요청이 나가지 않음")
	}
}

// 컴파일 타임 확인: AsVerificationError 가 감싼 에러도 풀어내는지(errors.As 경유)
// 최소 sanity.
func TestAsVerificationError_wrapped(t *testing.T) {
	base := &VerificationError{Reason: "테스트"}
	wrapped := errors.Join(errors.New("바깥"), base)
	if _, ok := AsVerificationError(wrapped); !ok {
		t.Error("감싼 VerificationError 를 풀어내지 못함")
	}
}
