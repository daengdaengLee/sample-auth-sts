// Package inbound 은 README 의 헥사고날 설계에서 "수신 어댑터(inbound adapter)"에
// 해당한다. HTTP 전송 계층을 담당해 요청을 받아 도메인 코어의 유스케이스로
// 넘기는 입구이며, 신뢰 판단 로직은 담지 않는다. 현재는 라우팅 골격만 두고
// 핸들러는 스텁 상태다.
package inbound

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// NewRouter 는 slog 기반 요청 로거, 패닉 복구, 그리고 서버가 노출하는 라우트를
// 등록한 gin 엔진을 만들어 반환한다. main 은 이 엔진을 http.Server 의 핸들러로
// 사용한다. auth 는 조립 지점에서 주입하는 인바운드 포트로, /auth 핸들러가
// 파싱한 서명 요청을 이 포트로 넘긴다.
func NewRouter(logger *slog.Logger, auth domain.Authenticator) *gin.Engine {
	engine := gin.New()

	// 직접 연결된 TCP 피어만 신뢰한다: X-Forwarded-For/X-Real-IP 를 무시해
	// 로그에 남는 클라이언트 IP 를 클라이언트가 위조하지 못하게 한다. 이후 이
	// 서버를 리버스 프록시 뒤에 두게 되면 신뢰할 프록시 CIDR 을 설정한다.
	engine.ForwardedByClientIP = false

	// RequestID 를 가장 앞에 둬, 접근 로그와 각 핸들러 로그가 동일한 request_id 를
	// 공유하도록 한다.
	engine.Use(RequestID(), requestLogger(logger), gin.Recovery())

	h := NewHandler(logger, auth)

	// /healthz 는 운영용 헬스체크다. /auth 는 서명된 요청을 코어로 넘겨 인증을
	// 수행한다. /verify 는 발급 JWT 검증 엔드포인트로, 아직 501 스텁이다.
	engine.GET("/healthz", h.Health)
	engine.POST("/auth", h.Authenticate)
	engine.POST("/verify", h.Verify)

	return engine
}

// Handler 는 수신 어댑터의 HTTP 핸들러 묶음이다. logger 와 함께 인바운드 포트
// (도메인 Authenticator)를 주입받아, 각 핸들러가 HTTP 요청에서 파싱한 값을
// 코어로 넘긴다.
type Handler struct {
	logger *slog.Logger
	auth   domain.Authenticator
}

// NewHandler 는 주어진 로거와 인바운드 포트로 Handler 를 만든다.
func NewHandler(logger *slog.Logger, auth domain.Authenticator) *Handler {
	return &Handler{logger: logger, auth: auth}
}

// Health 는 운영용 헬스체크 응답을 반환한다.
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Verify 는 서버가 발급한 JWT 의 유효성(서명/만료)과 클레임을 검증하는
// 엔드포인트다. 검증 로직이 붙기 전까지는 501 스텁이다.
func (h *Handler) Verify(c *gin.Context) {
	h.logger.InfoContext(c.Request.Context(), "verify 요청 수신 (미구현)")
	c.JSON(http.StatusNotImplemented, gin.H{"status": "not_implemented"})
}
