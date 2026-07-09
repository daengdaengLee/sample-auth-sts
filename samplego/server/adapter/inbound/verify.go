package inbound

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// verifyRequest 는 /verify 요청 본문(JSON 엔벨로프)이다. 검증할 서버 발급 JWT 를 token 에
// 담는다.
type verifyRequest struct {
	Token string `json:"token"`
}

// verifyResponse 는 검증 성공 시 토큰 클레임을 담는 응답 본문이다(HTTP 와이어 표현). 시각
// 클레임(exp/iat)은 authResponse 와 같은 관례로 RFC3339 문자열로 싣는다. 클레임을 추가/변경
// 하면 대칭 지점 issuer.claims 와 domain.VerifiedToken 도 함께 갱신한다(domain.VerifiedToken
// doc 참고).
type verifyResponse struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt string `json:"exp"`
	IssuedAt  string `json:"iat"`
	JTI       string `json:"jti"`
	Account   string `json:"account"`
	UserID    string `json:"user_id"`
}

// Verify 는 서버가 발급한 JWT 를 파싱해 인바운드 포트로 넘기고, 결과를 HTTP 로 매핑한다.
// 요청 엔벨로프 오류(파싱 실패/빈 토큰/상한 초과)는 도메인 호출 전에 4xx 로 거르고, 통과한
// 토큰만 코어로 넘긴다. 검증 실패(서명 무효/만료/클레임 불일치)는 401, 성공은 200 이다.
func (h *Handler) Verify(c *gin.Context) {
	ctx := c.Request.Context()

	var req verifyRequest
	if !h.bindJSONBody(c, &req) {
		return
	}

	// 빈 토큰은 검증할 대상이 없는 형식 오류이므로 코어 호출 전에 400 으로 거른다.
	if req.Token == "" {
		h.logger.InfoContext(ctx, "verify 요청 token 필드 비어 있음")
		writeError(c, http.StatusBadRequest, "invalid_body", "token 필드가 비어 있음")
		return
	}

	out, err := h.verify.VerifyToken(ctx, domain.VerifyTokenInput{Token: req.Token})
	if err != nil {
		h.writeVerifyError(c, err)
		return
	}

	claims := out.Claims
	c.JSON(http.StatusOK, verifyResponse{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		ExpiresAt: claims.ExpiresAt.Format(time.RFC3339),
		IssuedAt:  claims.IssuedAt.Format(time.RFC3339),
		JTI:       claims.JTI,
		Account:   claims.Account,
		UserID:    claims.UserID,
	})
}

// writeVerifyError 는 도메인/어댑터가 돌려준 에러를 HTTP 상태로 매핑해 응답한다. 무효 토큰
// (서명/구조 실패 domain.VerificationRejected, 만료/발급자/대상 불일치 domain.RejectionError)은
// 모두 401 로, 그 외 내부 오류는 500 으로 매핑한다.
func (h *Handler) writeVerifyError(c *gin.Context, err error) {
	ctx := c.Request.Context()

	if ve, ok := domain.AsVerificationRejected(err); ok {
		h.logger.InfoContext(ctx, "verify 토큰 무효", slog.String("reason", ve.Reason))
		writeError(c, http.StatusUnauthorized, "invalid_token", "토큰 검증에 실패함(서명 무효/구조 오류)")
		return
	}

	if re, ok := domain.AsRejection(err); ok {
		h.logger.InfoContext(ctx, "verify 거부", slog.String("reason", string(re.Reason)))
		writeError(c, http.StatusUnauthorized, string(re.Reason), re.Message)
		return
	}

	// 그 외는 인프라/내부 실패다. 검증 경로에는 외부 위임이 없어 실무상 거의 없지만, 예기치
	// 못한 오류를 성공/무효로 오분류하지 않도록 500 으로 매핑한다.
	h.logger.ErrorContext(ctx, "verify 처리 내부 오류", slog.Any("error", err))
	writeError(c, http.StatusInternalServerError, "internal_error", "토큰 검증 중 내부 오류")
}
