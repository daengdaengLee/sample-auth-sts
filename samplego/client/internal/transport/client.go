// Package transport 는 README "클라이언트 > 증명 생성 및 전송"의 5단계(전송)와 데모 왕복
// (/verify)를 맡는다. 서명된 엔벨로프를 서버 /auth 로 보내 발급 토큰을 받고, 선택적으로 그
// 토큰을 /verify 로 보내 클레임을 되받는다. 서버 응답의 성공/실패 와이어 형태
// (samplego/server/adapter/inbound 의 authResponse/verifyResponse/errorResponse)에 맞춰
// 디코드한다.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/client/internal/proof"
)

// maxResponseBytes 는 서버 응답 본문을 읽을 최대 바이트다. 토큰/클레임 응답은 작으므로 넉넉히
// 1 MiB 로 두고, 이를 넘으면 비정상으로 본다(메모리 고갈 방지).
const maxResponseBytes = 1 << 20

// AuthResult 는 /auth 성공 응답이다. 서버 authResponse 와 필드가 대응한다. ExpiresAt 은 서버가
// RFC3339 로 싣는 만료 시각을 파싱한 값이다.
type AuthResult struct {
	Token     string
	ExpiresAt time.Time
}

// Claims 는 /verify 성공 응답의 토큰 클레임이다. 서버 verifyResponse 와 필드가 대응한다.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt string `json:"exp"`
	IssuedAt  string `json:"iat"`
	JTI       string `json:"jti"`
	Account   string `json:"account"`
	UserID    string `json:"user_id"`
}

// APIError 는 서버가 돌려준 실패 응답(4xx/401)이다. 서버 errorResponse 의 error/message 와
// 상태코드를 담아, 호출부가 사유를 사람이 읽을 형태로 보고할 수 있게 한다.
type APIError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

// Error 는 error 인터페이스를 만족시킨다.
func (e *APIError) Error() string {
	return fmt.Sprintf("서버가 요청을 거부함(status=%d code=%s): %s", e.Status, e.Code, e.Message)
}

// Client 는 서버 주소와 http.Client 를 묶은 전송 클라이언트다. 제로 값 http.Client 도 쓸 수
// 있게 New 에서 nil 을 기본값으로 채운다.
type Client struct {
	serverAddr string
	httpClient *http.Client
}

// New 는 대상 서버 주소와 http.Client 로 Client 를 만든다. httpClient 가 nil 이면 기본
// http.Client 를 쓴다(타임아웃 없음이라 실행 경로는 타임아웃을 실은 클라이언트를 주입한다).
// serverAddr 의 후행 슬래시는 제거한다: 뒤에 "/auth" 를 붙일 때 "//auth" 가 되면 gin 이
// 리다이렉트/404 로 떨구므로, 호출부 입력과 무관하게 여기서 한 번 정규화한다.
func New(serverAddr string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{serverAddr: strings.TrimRight(serverAddr, "/"), httpClient: httpClient}
}

// PostAuth 는 서명된 엔벨로프를 /auth 로 보내 발급 토큰을 받는다. 200 이면 토큰/만료를,
// 4xx 면 *APIError 를, 전송/디코드 실패는 일반 에러를 돌려준다.
func (c *Client) PostAuth(ctx context.Context, env proof.Envelope) (AuthResult, error) {
	// authResponse 는 서버 성공 응답 형태다. expires_at 은 RFC3339 문자열이라 파싱해 시각으로
	// 돌려준다.
	var body struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := c.postJSON(ctx, "/auth", env, &body); err != nil {
		return AuthResult{}, err
	}

	expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		return AuthResult{}, fmt.Errorf("/auth 응답 expires_at 파싱 실패(%q): %w", body.ExpiresAt, err)
	}
	return AuthResult{Token: body.Token, ExpiresAt: expiresAt}, nil
}

// PostVerify 는 발급 토큰을 /verify 로 보내 클레임을 되받는다(데모 왕복). 200 이면 클레임을,
// 401 이면 *APIError 를 돌려준다.
func (c *Client) PostVerify(ctx context.Context, token string) (Claims, error) {
	reqBody := struct {
		Token string `json:"token"`
	}{Token: token}

	var claims Claims
	if err := c.postJSON(ctx, "/verify", reqBody, &claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// postJSON 은 reqBody 를 JSON 으로 path 에 POST 하고, 200 이면 dst 로 디코드한다. 200 이 아니면
// 응답 본문을 errorResponse 로 읽어 *APIError 를 돌려준다. 전송/인코드/디코드 실패는 일반
// 에러다. /auth 와 /verify 가 공유하는 요청/응답 관례를 한 곳에 둔다.
func (c *Client) postJSON(ctx context.Context, path string, reqBody, dst any) error {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("%s 요청 본문 마샬 실패: %w", path, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverAddr+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%s 요청 생성 실패: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s 전송 실패: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%s 응답 본문 읽기 실패: %w", path, err)
	}

	if resp.StatusCode != http.StatusOK {
		// 실패 응답은 errorResponse(error/message) 형태다. 본문이 그 형태가 아니어도 상태
		// 코드만으로 사유를 보고할 수 있게, 파싱 실패는 무시하고 상태를 채운다.
		apiErr := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(body, apiErr)
		return apiErr
	}

	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("%s 응답 JSON 파싱 실패: %w", path, err)
	}
	return nil
}
