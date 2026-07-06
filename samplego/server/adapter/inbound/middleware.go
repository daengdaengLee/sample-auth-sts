package inbound

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/logging"
)

// requestIDHeader 는 요청 ID 를 주고받는 헤더 이름이다. 들어온 값이 있으면
// 이어받아 호출 경계를 넘어 상관관계를 유지한다.
const requestIDHeader = "X-Request-Id"

// maxRequestIDLen 은 이어받는 request_id 의 최대 길이다. 클라이언트가 준 값을
// 그대로 로그/응답에 반영하므로, 로그 비대화를 막기 위해 상한을 둔다.
const maxRequestIDLen = 128

// RequestID 는 요청마다 request_id 를 만들어(또는 헤더에서 이어받아) context 와
// 응답 헤더에 실어준다. 이후 이 요청 흐름에서 남기는 모든 로그(InfoContext 등)에
// request_id 가 자동으로 붙는다. 들어온 값이 안전한 형식이 아니면 신뢰하지 않고
// 새로 생성해, 로그 오염이나 비대화를 막는다.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(requestIDHeader)
		if !isValidRequestID(id) {
			id = newRequestID()
		}

		ctx := logging.AppendCtx(c.Request.Context(), slog.String("request_id", id))
		c.Request = c.Request.WithContext(ctx)
		c.Header(requestIDHeader, id)

		c.Next()
	}
}

// isValidRequestID 는 이어받아도 안전한 request_id 인지 검사한다. 길이 1..128,
// 문자셋 [A-Za-z0-9_-] 만 허용한다(hex/UUID 형식 수용). 이 범위를 벗어난 값은
// 로그/응답 헤더에 그대로 싣기에 위험하므로 거부한다.
func isValidRequestID(id string) bool {
	if len(id) == 0 || len(id) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '-' || ch == '_':
		default:
			return false
		}
	}
	return true
}

// newRequestID 는 16바이트 난수를 hex 로 인코딩한 요청 ID 를 만든다.
func newRequestID() string {
	b := make([]byte, 16)
	// crypto/rand.Read 는 실패하지 않는 것으로 문서화되어 있어 에러는 무시한다.
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// requestLogger 는 slog 를 통해 요청당 한 줄씩 로그를 남겨, 서버의 나머지
// 부분과 로그 출력을 일관되게 유지한다. InfoContext 로 요청 context 를 넘겨,
// RequestID 가 심은 request_id 가 접근 로그에도 붙게 한다.
func requestLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		logger.InfoContext(c.Request.Context(), "request",
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("latency", time.Since(start)),
			slog.String("client_ip", c.ClientIP()),
		)
	}
}
