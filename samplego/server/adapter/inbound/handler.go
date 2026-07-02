package inbound

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler 는 수신 어댑터의 HTTP 핸들러 묶음이다. 지금은 logger 만 갖지만, 이후
// 인바운드 포트("인증 요청을 처리한다" 유스케이스) 등 코어 의존성을 여기에
// 주입해 각 핸들러가 파싱한 값을 코어로 넘기게 된다.
type Handler struct {
	logger *slog.Logger
}

// NewHandler 는 주어진 로거로 Handler 를 만든다.
func NewHandler(logger *slog.Logger) *Handler {
	return &Handler{logger: logger}
}

// Health 는 운영용 헬스체크 응답을 반환한다.
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Authenticate 는 서명된 GetCallerIdentity 요청을 받아 인증을 처리하는
// 엔드포인트다. 이후 여기서 바인딩 헤더 값/메서드/바디/액션/서명 시각을 추출하고
// 원본 서명 요청을 보존한 뒤 인바운드 포트를 호출하게 된다. 코어가 붙기 전까지는
// 501 스텁이다.
func (h *Handler) Authenticate(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"status": "not_implemented"})
}

// Verify 는 서버가 발급한 JWT 의 유효성(서명/만료)과 클레임을 검증하는
// 엔드포인트다. 검증 로직이 붙기 전까지는 501 스텁이다.
func (h *Handler) Verify(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"status": "not_implemented"})
}
