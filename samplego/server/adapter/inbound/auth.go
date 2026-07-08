package inbound

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/sts"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

const (
	// authorizationHeader 는 SigV4 서명 정보를 싣는 헤더 이름이다. 여기서 SignedHeaders
	// 목록을 파싱해, 신선도/바인딩 근거 헤더가 서명 범위 안에 있는지 검증한다.
	authorizationHeader = "Authorization"

	// bindingHeader 는 서버 바인딩 값을 싣는 헤더 이름이다. 클라이언트는 이 헤더를 SigV4
	// 서명 범위(SignedHeaders)에 포함해야 하며, 서버는 그 값이 자신만의 고유 기대값과
	// 일치하는지 코어에서 대조한다(혼동된 대리자 완화).
	bindingHeader = "X-Server-Binding"

	// amzDateHeader 는 SigV4 서명 시각을 싣는 헤더 이름이다. 신선도 판단의 근거(SignedAt)이며,
	// 위변조를 막으려면 서명 범위에 포함돼야 한다.
	amzDateHeader = "X-Amz-Date"

	// amzDateFormat 은 X-Amz-Date 의 ISO8601 basic 형식이다(예: 20260708T120000Z).
	amzDateFormat = "20060102T150405Z"
)

// authRequest 는 /auth 요청 본문(JSON 엔벨로프)이다. 클라이언트가 SigV4 로 서명한 원본
// GetCallerIdentity 요청을 재구성 없이 그대로 담아, 서버가 STS 로 위임할 수 있게 한다. body 는
// 서명 대상 바이트를 정확히 보존하려고 base64(표준 인코딩)로 싣는다.
type authRequest struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

// authResponse 는 인증 성공 시 발급된 자격을 담는 응답 본문이다. expires_at 은 RFC3339 다.
type authResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// errorResponse 는 실패 응답 본문이다. error 는 짧은 사유 식별자, message 는 사람이 읽을 설명이다.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Authenticate 는 서명된 GetCallerIdentity 요청(JSON 엔벨로프)을 파싱해 인바운드 포트로 넘기고,
// 결과를 HTTP 로 매핑한다. 도메인 호출 전에 엔벨로프 파싱과 서명 범위(SignedHeaders) 사전검증을
// 먼저 하고, 통과한 값만 코어로 넘긴다.
func (h *Handler) Authenticate(c *gin.Context) {
	ctx := c.Request.Context()

	var req authRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.InfoContext(ctx, "auth 요청 본문 파싱 실패", slog.Any("error", err))
		writeError(c, http.StatusBadRequest, "invalid_body", "요청 본문 JSON 파싱 실패")
		return
	}

	// 서명 대상 바이트를 그대로 되살리려고 base64 로 디코드한다. STS 는 이 바이트에 대해
	// 서명을 재검증하므로, 한 바이트라도 어긋나면 위임이 거절된다.
	body, err := base64.StdEncoding.DecodeString(req.Body)
	if err != nil {
		h.logger.InfoContext(ctx, "auth 요청 body base64 디코드 실패", slog.Any("error", err))
		writeError(c, http.StatusBadRequest, "invalid_body", "body 는 base64(표준 인코딩)여야 함")
		return
	}

	// SigV4 SignedHeaders 목록을 뽑는다. 서명 밖에서 주입된 헤더는 STS 가 서명 검증에서
	// 무시하므로, 신선도/바인딩 근거 헤더가 이 목록 안에 있는지 확인해 위변조 우회를 막는다.
	authz, _ := headerLookup(req.Headers, authorizationHeader)
	signed := signedHeaderSet(authz)
	if len(signed) == 0 {
		h.logger.InfoContext(ctx, "auth 요청 SignedHeaders 해석 불가")
		writeError(c, http.StatusBadRequest, "invalid_signature", "Authorization 헤더의 SignedHeaders 를 해석할 수 없음")
		return
	}

	// 신선도 근거(SignedAt)는 서명된 X-Amz-Date 에서만 얻는다. 서명 범위 밖 날짜는 위조로
	// 신선도를 되살릴 수 있으므로 거부한다.
	rawDate, ok := headerLookup(req.Headers, amzDateHeader)
	if !ok || !signed[strings.ToLower(amzDateHeader)] {
		h.logger.InfoContext(ctx, "auth 요청 X-Amz-Date 부재/미서명", slog.Bool("present", ok))
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-Date 가 없거나 서명 범위에 포함되지 않음")
		return
	}
	signedAt, err := time.Parse(amzDateFormat, rawDate)
	if err != nil {
		h.logger.InfoContext(ctx, "auth 요청 X-Amz-Date 파싱 실패", slog.Any("error", err))
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-Date 형식이 올바르지 않음")
		return
	}

	// 바인딩 헤더가 없거나 서명 범위 밖이면, 이 증명이 이 서버로 바인딩됐다고 볼 수 없다
	// (혼동된 대리자). 값 대조(코어) 이전에 서명 범위 밖 주입을 여기서 거부한다.
	binding, ok := headerLookup(req.Headers, bindingHeader)
	if !ok || !signed[strings.ToLower(bindingHeader)] {
		h.logger.WarnContext(ctx, "바인딩 헤더가 서명 범위에 없음", slog.Bool("present", ok))
		writeError(c, http.StatusForbidden, "binding_not_signed", "서버 바인딩 헤더가 없거나 서명 범위에 포함되지 않음")
		return
	}

	// Action 은 위임 형태 검증(코어 3단계)용 추출값이다. 파싱 실패/부재면 빈 값으로 두어,
	// 코어가 invalid_shape 로 거르게 한다.
	action := ""
	if form, err := url.ParseQuery(string(body)); err == nil {
		action = form.Get("Action")
	}

	out, err := h.auth.Authenticate(ctx, domain.AuthenticateInput{
		Request: domain.SignedRequest{
			BindingValue: binding,
			Method:       req.Method,
			Action:       action,
			SignedAt:     signedAt,
			Original: domain.PreservedRequest{
				Method: req.Method,
				URL:    req.URL,
				Header: req.Headers,
				Body:   body,
			},
		},
	})
	if err != nil {
		h.writeAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, authResponse{
		Token:     out.Credential.Token,
		ExpiresAt: out.Credential.ExpiresAt.Format(time.RFC3339),
	})
}

// writeAuthError 는 도메인/어댑터가 돌려준 에러를 HTTP 상태로 매핑해 응답한다. 로컬 거부
// (RejectionError)는 사유별 4xx 로, STS 검증 실패(VerificationError)는 401 무자격으로, 그 외
// 인프라 오류는 502 로 매핑한다.
func (h *Handler) writeAuthError(c *gin.Context, err error) {
	ctx := c.Request.Context()

	if re, ok := domain.AsRejection(err); ok {
		status := rejectionStatus(re.Reason)
		h.logger.InfoContext(ctx, "auth 거부", slog.String("reason", string(re.Reason)), slog.Int("status", status))
		writeError(c, status, string(re.Reason), re.Message)
		return
	}

	if ve, ok := sts.AsVerificationError(err); ok {
		h.logger.InfoContext(ctx, "STS 신원 검증 실패", slog.String("reason", ve.Reason), slog.Int("sts_status", ve.HTTPStatus))
		writeError(c, http.StatusUnauthorized, "verification_failed", "STS 가 서명된 요청을 검증하지 못함")
		return
	}

	// 그 외는 인프라 실패다. 현재 어댑터는 STS 전송 오류와 issuer 내부 오류를 타입으로
	// 구분하지 않으므로(둘 다 일반 오류), 위임 upstream 실패로 보고 502 로 매핑한다. issuer
	// 내부 실패(crypto/rand, json.Marshal)는 실무상 거의 없어 무시 가능한 부정확이다.
	h.logger.ErrorContext(ctx, "auth 처리 인프라 오류", slog.Any("error", err))
	writeError(c, http.StatusBadGateway, "upstream_error", "인증 처리 중 인프라 오류")
}

// rejectionStatus 는 로컬 거부 사유를 HTTP 상태로 매핑한다. 형태 불량은 400, 신선도 초과는
// 401, 바인딩 불일치/허용되지 않은 ARN 은 403 이다.
func rejectionStatus(reason domain.RejectionReason) int {
	switch reason {
	case domain.ReasonInvalidShape:
		return http.StatusBadRequest
	case domain.ReasonStale:
		return http.StatusUnauthorized
	case domain.ReasonBindingMismatch, domain.ReasonARNNotAllowed:
		return http.StatusForbidden
	default:
		return http.StatusForbidden
	}
}

// writeError 는 실패 응답을 JSON 으로 쓴다.
func writeError(c *gin.Context, status int, reason, message string) {
	c.JSON(status, errorResponse{Error: reason, Message: message})
}

// headerLookup 은 헤더 맵에서 name 을 대소문자 무시로 찾아 첫 값을 돌려준다. 값이 없으면
// (키 부재 또는 빈 슬라이스) false 를 돌려준다.
func headerLookup(h map[string][]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0], true
		}
	}
	return "", false
}

// signedHeaderSet 은 SigV4 Authorization 헤더 값에서 SignedHeaders 구간을 찾아, 세미콜론으로
// 구분된 헤더 이름들을 소문자 집합으로 돌려준다. SignedHeaders 를 찾지 못하거나 비면 nil 을
// 돌려준다. Authorization 형식 예:
// "AWS4-HMAC-SHA256 Credential=..., SignedHeaders=host;x-amz-date;x-server-binding, Signature=..."
func signedHeaderSet(authorization string) map[string]bool {
	const marker = "SignedHeaders="
	i := strings.Index(authorization, marker)
	if i < 0 {
		return nil
	}
	rest := authorization[i+len(marker):]
	// SignedHeaders 값은 다음 콤마(", Signature=...") 전까지다.
	if j := strings.IndexByte(rest, ','); j >= 0 {
		rest = rest[:j]
	}
	set := make(map[string]bool)
	for _, name := range strings.Split(rest, ";") {
		if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
			set[n] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}
