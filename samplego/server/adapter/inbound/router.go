// Package inbound 은 README 의 헥사고날 설계에서 "수신 어댑터(inbound adapter)"에
// 해당한다. HTTP 전송 계층을 담당해 요청을 받아 도메인 코어의 유스케이스로
// 넘기는 입구이며, 신뢰 판단 로직은 담지 않는다. 현재는 라우팅 골격만 두고
// 핸들러는 스텁 상태다.
package inbound

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

// NewRouter 는 slog 기반 요청 로거, 패닉 복구, 그리고 서버가 노출하는 라우트를
// 등록한 gin 엔진을 만들어 반환한다. main 은 이 엔진을 http.Server 의 핸들러로
// 사용한다.
func NewRouter(logger *slog.Logger) *gin.Engine {
	engine := gin.New()

	// 직접 연결된 TCP 피어만 신뢰한다: X-Forwarded-For/X-Real-IP 를 무시해
	// 로그에 남는 클라이언트 IP 를 클라이언트가 위조하지 못하게 한다. 이후 이
	// 서버를 리버스 프록시 뒤에 두게 되면 신뢰할 프록시 CIDR 을 설정한다.
	engine.ForwardedByClientIP = false

	engine.Use(requestLogger(logger), gin.Recovery())

	h := NewHandler(logger)

	// /healthz 는 운영용 헬스체크다. /auth 와 /verify 는 README 설계의 기능
	// 엔드포인트로, 코어/PoP/STS 로직이 붙기 전까지는 501 스텁으로 둔다.
	engine.GET("/healthz", h.Health)
	engine.POST("/auth", h.Authenticate)
	engine.POST("/verify", h.Verify)

	return engine
}
