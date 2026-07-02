package inbound

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// requestLogger 는 slog 를 통해 요청당 한 줄씩 로그를 남겨, 서버의 나머지
// 부분과 로그 출력을 일관되게 유지한다.
func requestLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		logger.Info("request",
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("latency", time.Since(start)),
			slog.String("client_ip", c.ClientIP()),
		)
	}
}
