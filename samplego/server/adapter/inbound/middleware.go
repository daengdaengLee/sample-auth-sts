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

// RequestID 는 요청마다 request_id 를 만들어(또는 헤더에서 이어받아) context 와
// 응답 헤더에 실어준다. 이후 이 요청 흐름에서 남기는 모든 로그(InfoContext 등)에
// request_id 가 자동으로 붙는다.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(requestIDHeader)
		if id == "" {
			id = newRequestID()
		}

		ctx := logging.AppendCtx(c.Request.Context(), slog.String("request_id", id))
		c.Request = c.Request.WithContext(ctx)
		c.Header(requestIDHeader, id)

		c.Next()
	}
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
