package inbound

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

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

	// amzDateHeader 는 SigV4 서명 시각을 싣는 헤더 이름이다. 헤더 기반에서는 신선도 판단의
	// 근거(SignedAt)이며, 위변조를 막으려면 서명 범위에 포함돼야 한다. presigned 에서는 같은
	// 이름이 URL 쿼리 파라미터로 실린다(아래 presigned 쿼리 상수 참고).
	amzDateHeader = "X-Amz-Date"

	// amzDateFormat 은 X-Amz-Date 의 ISO8601 basic 형식이다(예: 20260708T120000Z). 두 형태가
	// 같은 형식을 쓴다.
	amzDateFormat = "20060102T150405Z"

	// presigned(pre-signed URL) 형태의 SigV4 정보는 Authorization 헤더가 아니라 URL 쿼리
	// 파라미터로 실린다. X-Amz-Algorithm 존재로 형태를 판별하고, X-Amz-SignedHeaders 를 서명
	// 범위로, X-Amz-Date + X-Amz-Expires 를 신선도 근거로, Credential/Signature 존재를 확인한다.
	// Action 은 쿼리에서 뽑는다(헤더 기반은 폼 바디에서 뽑는 것과 대칭). 이 값들은 canonical
	// 쿼리 문자열에 들어 서명 범위에 포함되므로 위변조 시 STS 가 서명 재검증에서 거절한다.
	amzAlgorithmParam     = "X-Amz-Algorithm"
	amzCredentialParam    = "X-Amz-Credential"
	amzDateParam          = "X-Amz-Date"
	amzExpiresParam       = "X-Amz-Expires"
	amzSignedHeadersParam = "X-Amz-SignedHeaders"
	amzSignatureParam     = "X-Amz-Signature"
	queryActionKey        = "Action"

	// maxPresignExpirySeconds 는 받아들일 X-Amz-Expires 의 상한(초)이다. AWS 도 presigned URL
	// 만료를 최대 7일로 두므로 이를 상한으로 삼는다. 서버는 어차피 자체 최대 age 와 교집합(min)을
	// 취하므로 이보다 큰 만료는 의미가 없고, 상한이 없으면 거대한 값이 time.Duration(int64 ns) 곱셈
	// 에서 오버플로할 수 있어 여기서 거른다.
	maxPresignExpirySeconds = 7 * 24 * 60 * 60

	// maxBodyBytes 는 수신 어댑터가 받는 JSON 요청 본문의 최대 바이트다(/auth 서명 엔벨로프,
	// /verify 토큰 모두 작으므로 넉넉히 1 MiB). 넘으면 413 으로 거부한다. 상한이 없으면 거대한
	// 본문으로 메모리를 고갈시키는 값싼 DoS 가 가능하다(STS 응답 상한 maxResponseBytes 와 같은 톤).
	maxBodyBytes = 1 << 20
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

// extractedProof 는 두 증명 형태(header/presigned)에서 공통으로 뽑아 코어로 넘길 스칼라
// 묶음이다. 형태 판별 후 형태별 추출기가 이 값을 채우면, 공통 코어 투입 경로가 형태를
// 신경 쓰지 않고 하나로 흐른다(형태별 특수분기를 추출 계층에만 가둔다).
type extractedProof struct {
	form     domain.ProofForm
	binding  string
	signedAt time.Time
	action   string
	expiry   time.Duration // presigned 만 채운다(header 는 0)
}

// Authenticate 는 서명된 GetCallerIdentity 요청(JSON 엔벨로프)을 파싱해 인바운드 포트로 넘기고,
// 결과를 HTTP 로 매핑한다. 도메인 호출 전에 엔벨로프 파싱과 증명 형태 판별/사전검증을 먼저 하고,
// 통과한 값만 공통으로 코어에 넘긴다. 형태 판별은 Authorization 헤더(헤더 기반) 대 X-Amz-Algorithm
// 쿼리(presigned)로 가른다.
func (h *Handler) Authenticate(c *gin.Context) {
	ctx := c.Request.Context()

	var req authRequest
	if !h.bindJSONBody(c, &req) {
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

	// 형태 판별 -> 형태별 추출기로 분기한다. 지원 형태는 헤더 기반(Authorization 헤더)과 presigned
	// (URL 쿼리 서명) 둘뿐이므로, Authorization 헤더가 있으면 헤더 기반, 없으면 presigned 로 시도한다.
	// presigned 도 아니면(X-Amz-Algorithm 쿼리 부재) extractPresignedForm 이 형태 판별 불가로 거부한다.
	// 추출기는 실패 시 스스로 응답을 쓰고 false 를 돌려준다(호출부는 즉시 return).
	var (
		p  extractedProof
		ok bool
	)
	if len(headerValues(req.Headers, authorizationHeader)) > 0 {
		p, ok = h.extractHeaderForm(c, req, body)
	} else {
		p, ok = h.extractPresignedForm(c, req)
	}
	if !ok {
		return
	}

	out, err := h.auth.Authenticate(ctx, domain.AuthenticateInput{
		Request: domain.SignedRequest{
			Form:         p.form,
			BindingValue: p.binding,
			Method:       req.Method,
			Action:       p.action,
			SignedAt:     p.signedAt,
			Expiry:       p.expiry,
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

// extractHeaderForm 은 헤더 기반 서명(Authorization 헤더에 SignedHeaders)에서 신선도/바인딩
// 근거를 뽑는다. 서명 밖에서 주입된 헤더는 STS 가 서명 검증에서 무시하므로, X-Amz-Date/바인딩
// 헤더가 SignedHeaders 목록 안에 있는지 함께 확인해 위변조 우회를 막는다. 실패 시 응답을 쓰고
// ok=false 를 돌려준다.
func (h *Handler) extractHeaderForm(c *gin.Context, req authRequest, body []byte) (extractedProof, bool) {
	ctx := c.Request.Context()

	// 보안 관련 헤더는 정확히 1개 값만 허용한다. 대소문자만 다른 중복 키(예: X-Amz-Date 와
	// x-amz-date)는 서로 다른 JSON 키로 언마샬되어, 첫 값을 취하면 어느 값이 뽑힐지 맵 순회
	// 순서에 따라 비결정적이 된다. STS 는 canonical 화 시 모든 값을 합치므로, 로컬 판단과
	// 어긋나지 않도록 다중 값을 아예 거부한다.
	authzVals := headerValues(req.Headers, authorizationHeader)
	if len(authzVals) != 1 {
		h.logger.InfoContext(ctx, "auth 요청 Authorization 헤더 값 개수 비정상", slog.Int("count", len(authzVals)))
		writeError(c, http.StatusBadRequest, "invalid_signature", "Authorization 헤더가 없거나 값이 2개 이상임")
		return extractedProof{}, false
	}

	// SigV4 SignedHeaders 목록을 뽑는다. 서명 밖에서 주입된 헤더는 STS 가 서명 검증에서
	// 무시하므로, 신선도/바인딩 근거 헤더가 이 목록 안에 있는지 확인해 위변조 우회를 막는다.
	signed := signedHeaderSet(authzVals[0])
	if len(signed) == 0 {
		h.logger.InfoContext(ctx, "auth 요청 SignedHeaders 해석 불가")
		writeError(c, http.StatusBadRequest, "invalid_signature", "Authorization 헤더의 SignedHeaders 를 해석할 수 없음")
		return extractedProof{}, false
	}

	// 신선도 근거(SignedAt)는 서명된 X-Amz-Date 에서만 얻는다. 서명 범위 밖 날짜는 위조로
	// 신선도를 되살릴 수 있으므로 거부한다.
	rawDate, count, ok := singleSignedValue(req.Headers, signed, amzDateHeader)
	if !ok {
		h.logger.InfoContext(ctx, "auth 요청 X-Amz-Date 부재/다중/미서명", slog.Int("count", count))
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-Date 가 없거나 값이 2개 이상이거나 서명 범위에 포함되지 않음")
		return extractedProof{}, false
	}
	signedAt, err := time.Parse(amzDateFormat, rawDate)
	if err != nil {
		h.logger.InfoContext(ctx, "auth 요청 X-Amz-Date 파싱 실패", slog.Any("error", err))
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-Date 형식이 올바르지 않음")
		return extractedProof{}, false
	}

	// 바인딩 헤더가 없거나(또는 다중이거나) 서명 범위 밖이면, 이 증명이 이 서버로 바인딩됐다고
	// 볼 수 없다(혼동된 대리자). 값 대조(코어) 이전에 여기서 거부한다.
	binding, ok := h.signedBinding(c, req.Headers, signed)
	if !ok {
		return extractedProof{}, false
	}

	return extractedProof{
		form:     domain.FormHeader,
		binding:  binding,
		signedAt: signedAt,
		action:   actionFromForm(string(body)),
	}, true
}

// extractPresignedForm 은 pre-signed URL 형태에서 신선도/만료/바인딩 근거를 URL 쿼리에서 뽑는다.
// Authorization 헤더 대신 X-Amz-SignedHeaders 를 서명 범위로, X-Amz-Date + X-Amz-Expires 를
// 신선도/만료 근거로, X-Amz-Algorithm/Credential/Signature 존재를 확인한다. 바인딩은 실제 헤더로
// 존재하면서 동시에 X-Amz-SignedHeaders 목록에 있어야 통과한다(없거나 미서명이면 binding_not_signed).
// 날짜/만료 자체는 canonical 쿼리에 실려 서명 범위에 들어가므로(위변조 시 STS 가 거절) SignedHeaders
// 목록 포함까지는 요구하지 않는다. 실패 시 응답을 쓰고 ok=false 를 돌려준다.
func (h *Handler) extractPresignedForm(c *gin.Context, req authRequest) (extractedProof, bool) {
	ctx := c.Request.Context()

	u, err := url.Parse(req.URL)
	if err != nil {
		h.logger.InfoContext(ctx, "auth 요청 presigned URL 파싱 실패", slog.Any("error", err))
		writeError(c, http.StatusBadRequest, "invalid_signature", "presigned URL 을 해석할 수 없음")
		return extractedProof{}, false
	}
	q := u.Query()

	// 형태 게이트: presigned 는 URL 쿼리에 X-Amz-Algorithm 을 실는다. Authorization 헤더가 없는데
	// 이마저 없으면 지원하는 두 형태 어디에도 해당하지 않으므로, 형태 판별 불가로 거부한다.
	if !q.Has(amzAlgorithmParam) {
		h.logger.InfoContext(ctx, "auth 요청 증명 형태 판별 불가")
		writeError(c, http.StatusBadRequest, "invalid_signature", "증명 형태를 판별할 수 없음(Authorization 헤더도 presigned 쿼리도 없음)")
		return extractedProof{}, false
	}

	// SigV4 쿼리 서명의 필수 파라미터가 각각 정확히 1개로 존재하는지 확인한다(파라미터 오염
	// 방지). 값 자체의 유효성은 STS 가 서명 재검증에서 본다.
	for _, name := range []string{amzAlgorithmParam, amzCredentialParam, amzSignatureParam} {
		if len(q[name]) != 1 {
			h.logger.InfoContext(ctx, "auth 요청 presigned 필수 쿼리 파라미터 부재/다중", slog.String("param", name), slog.Int("count", len(q[name])))
			writeError(c, http.StatusBadRequest, "invalid_signature", "presigned SigV4 쿼리 파라미터가 없거나 값이 2개 이상임")
			return extractedProof{}, false
		}
	}

	// 서명 범위(SignedHeaders)는 X-Amz-SignedHeaders 쿼리에서 얻는다. 헤더 기반의 Authorization
	// SignedHeaders 와 같은 세미콜론 목록이라 같은 헬퍼로 파싱한다.
	rawSignedHeaders, ok := singleQueryValue(q, amzSignedHeadersParam)
	if !ok {
		h.logger.InfoContext(ctx, "auth 요청 X-Amz-SignedHeaders 부재/다중")
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-SignedHeaders 가 없거나 값이 2개 이상임")
		return extractedProof{}, false
	}
	signed := parseSignedHeaderList(rawSignedHeaders)
	if len(signed) == 0 {
		h.logger.InfoContext(ctx, "auth 요청 X-Amz-SignedHeaders 해석 불가")
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-SignedHeaders 를 해석할 수 없음")
		return extractedProof{}, false
	}

	// 신선도 근거(SignedAt)는 X-Amz-Date 쿼리에서 얻는다.
	rawDate, ok := singleQueryValue(q, amzDateParam)
	if !ok {
		h.logger.InfoContext(ctx, "auth 요청 presigned X-Amz-Date 부재/다중")
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-Date 가 없거나 값이 2개 이상임")
		return extractedProof{}, false
	}
	signedAt, err := time.Parse(amzDateFormat, rawDate)
	if err != nil {
		h.logger.InfoContext(ctx, "auth 요청 presigned X-Amz-Date 파싱 실패", slog.Any("error", err))
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-Date 형식이 올바르지 않음")
		return extractedProof{}, false
	}

	// 만료 근거(Expiry)는 X-Amz-Expires 쿼리에서 얻는다(초 단위 양의 정수, 상한 이내). 서버는 이
	// 값을 맹신하지 않고 자체 최대 age 와 교집합으로만 반영하지만(코어 4단계), 형식/부호/상한은
	// 여기서 건다. 상한(maxPresignExpirySeconds)은 초 단위를 time.Duration(ns) 으로 곱할 때의
	// 오버플로도 함께 막는다.
	rawExpires, ok := singleQueryValue(q, amzExpiresParam)
	if !ok {
		h.logger.InfoContext(ctx, "auth 요청 X-Amz-Expires 부재/다중")
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-Expires 가 없거나 값이 2개 이상임")
		return extractedProof{}, false
	}
	expSecs, err := strconv.Atoi(rawExpires)
	if err != nil || expSecs <= 0 || expSecs > maxPresignExpirySeconds {
		h.logger.InfoContext(ctx, "auth 요청 X-Amz-Expires 형식/부호/상한 불량", slog.String("value", rawExpires))
		writeError(c, http.StatusBadRequest, "invalid_signature", "X-Amz-Expires 는 양의 정수(초)이고 상한 이내여야 함")
		return extractedProof{}, false
	}

	// 바인딩 헤더가 실제 헤더로 존재하고 동시에 X-Amz-SignedHeaders 목록에 있어야 통과한다.
	// presigned 에서 바인딩 값은 쿼리가 아니라 실제 HTTP 헤더로 실리므로, 서명 범위(SignedHeaders)
	// 안에 없으면 전달 과정에서 값이 바뀌어도 서명이 깨지지 않아 혼동된 대리자 완화가 무력화된다.
	binding, ok := h.signedBinding(c, req.Headers, signed)
	if !ok {
		return extractedProof{}, false
	}

	// Action 은 헤더 기반이 폼 바디에서 뽑는 것과 대칭으로 URL 쿼리에서 뽑는다. 정확히 1개일
	// 때만 채우고, 부재/중복이면 빈 값으로 두어 코어가 invalid_shape 로 거르게 한다.
	action := ""
	if vals := q[queryActionKey]; len(vals) == 1 {
		action = vals[0]
	}

	return extractedProof{
		form:     domain.FormPresigned,
		binding:  binding,
		signedAt: signedAt,
		action:   action,
		expiry:   time.Duration(expSecs) * time.Second,
	}, true
}

// writeAuthError 는 도메인/어댑터가 돌려준 에러를 HTTP 상태로 매핑해 응답한다. 로컬 거부
// (domain.RejectionError)는 사유별 4xx 로, 위임 검증 무자격(domain.VerificationRejected)은
// 401 로, 그 외 인프라 오류는 502 로 매핑한다.
func (h *Handler) writeAuthError(c *gin.Context, err error) {
	ctx := c.Request.Context()

	if re, ok := domain.AsRejection(err); ok {
		status := rejectionStatus(re.Reason)
		h.logger.InfoContext(ctx, "auth 거부", slog.String("reason", string(re.Reason)), slog.Int("status", status))
		writeError(c, status, string(re.Reason), re.Message)
		return
	}

	if ve, ok := domain.AsVerificationRejected(err); ok {
		h.logger.InfoContext(ctx, "신원 검증 무자격", slog.String("reason", ve.Reason))
		writeError(c, http.StatusUnauthorized, "verification_failed", "신원 검증에 실패함(서명 무효/만료 등)")
		return
	}

	// 그 외는 인프라 실패다. 현재 어댑터는 STS 전송 오류와 issuer 내부 오류를 타입으로
	// 구분하지 않으므로(둘 다 일반 오류), 위임 upstream 실패로 보고 502 로 매핑한다. issuer
	// 내부 실패(crypto/rand, json.Marshal)는 실무상 거의 없어 무시 가능한 부정확이다.
	h.logger.ErrorContext(ctx, "auth 처리 인프라 오류", slog.Any("error", err))
	writeError(c, http.StatusBadGateway, "upstream_error", "인증 처리 중 인프라 오류")
}

// rejectionStatus 는 로컬 거부 사유를 HTTP 상태로 매핑한다. 형태 불량은 400, 신선도 초과는
// 401 이다. 그 외(바인딩 불일치/허용되지 않은 ARN, 그리고 향후 추가될 미분류 사유)는 안전하게
// 거부(403)로 매핑한다.
func rejectionStatus(reason domain.RejectionReason) int {
	switch reason {
	case domain.ReasonInvalidShape:
		return http.StatusBadRequest
	case domain.ReasonStale:
		return http.StatusUnauthorized
	default:
		return http.StatusForbidden
	}
}

// writeError 는 실패 응답을 JSON 으로 쓴다.
func writeError(c *gin.Context, status int, reason, message string) {
	c.JSON(status, errorResponse{Error: reason, Message: message})
}

// bindJSONBody 는 요청 본문을 maxBodyBytes 로 제한한 뒤 JSON 으로 dst 에 바인딩한다. 상한
// 초과(*http.MaxBytesError)는 413, 그 외 파싱 실패는 400 으로 응답하고 false 를 돌려준다
// (호출부는 즉시 return). 성공 시 true. /auth 와 /verify 가 공유하는 본문 파싱 관례라, 상한/
// 상태 매핑을 한 곳에 둔다. 로그는 경로 중립 문구를 쓴다(접근 로그에 이미 path 가 있음).
func (h *Handler) bindJSONBody(c *gin.Context, dst any) bool {
	ctx := c.Request.Context()

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	if err := c.ShouldBindJSON(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.logger.InfoContext(ctx, "요청 본문이 상한 초과", slog.Int64("limit", tooLarge.Limit))
			writeError(c, http.StatusRequestEntityTooLarge, "body_too_large", "요청 본문이 허용 크기를 초과함")
			return false
		}
		h.logger.InfoContext(ctx, "요청 본문 JSON 파싱 실패", slog.Any("error", err))
		writeError(c, http.StatusBadRequest, "invalid_body", "요청 본문 JSON 파싱 실패")
		return false
	}
	return true
}

// headerValues 는 헤더 맵에서 name 과 대소문자 무시로 일치하는 모든 키의 값을 하나로 모아
// 돌려준다. 대소문자만 다른 중복 키(JSON 이 서로 다른 키로 언마샬)까지 합쳐, 보안 관련 헤더의
// "정확히 1개" 검사가 중복 주입을 놓치지 않게 한다.
func headerValues(h map[string][]string, name string) []string {
	var vals []string
	for k, v := range h {
		if strings.EqualFold(k, name) {
			vals = append(vals, v...)
		}
	}
	return vals
}

// singleSignedValue 는 name 헤더가 정확히 1개 값이고 그 헤더가 SigV4 SignedHeaders 목록에
// 포함됐는지 확인해 그 값을 돌려준다. 조건을 못 맞추면 ok=false 와 값 개수를 준다(호출부가
// 상태코드/식별자/메시지를 정함). 서명 밖 다중값/주입 헤더를 신선도/바인딩 근거로 쓰지 않도록
// 막는 date/binding 공통 검사다. Authorization 은 signed 를 만들어내는 단계라 여기 쓰지 않는다.
func singleSignedValue(h map[string][]string, signed map[string]bool, name string) (string, int, bool) {
	vals := headerValues(h, name)
	if len(vals) != 1 || !signed[strings.ToLower(name)] {
		return "", len(vals), false
	}
	return vals[0], len(vals), true
}

// singleQueryValue 는 쿼리 파라미터 key 가 정확히 1개 값일 때 그 값을 돌려준다. 부재/다중이면
// ok=false 다. presigned 쿼리 파라미터의 "정확히 1개" 검사(파라미터 오염 방지)에 쓴다.
func singleQueryValue(q url.Values, key string) (string, bool) {
	vals := q[key]
	if len(vals) != 1 {
		return "", false
	}
	return vals[0], true
}

// signedBinding 은 바인딩 헤더가 실제 헤더로 정확히 1개 존재하면서 SigV4 서명 범위(SignedHeaders)
// 에 포함되는지 확인해 그 값을 돌려준다. 두 형태(header/presigned)가 공유하는 혼동된 대리자 검사로,
// 서명 범위 밖 바인딩은 전달 과정에서 값이 바뀌어도 서명이 깨지지 않아 완화가 무력화되므로 거부한다.
// 실패 시 스스로 응답(403 binding_not_signed)을 쓰고 ok=false 를 돌려준다.
func (h *Handler) signedBinding(c *gin.Context, headers map[string][]string, signed map[string]bool) (string, bool) {
	binding, count, ok := singleSignedValue(headers, signed, bindingHeader)
	if !ok {
		h.logger.WarnContext(c.Request.Context(), "바인딩 헤더가 없거나 다중이거나 서명 범위 밖", slog.Int("count", count))
		writeError(c, http.StatusForbidden, "binding_not_signed", "서버 바인딩 헤더가 없거나 값이 2개 이상이거나 서명 범위에 포함되지 않음")
		return "", false
	}
	return binding, true
}

// actionFromForm 은 POST 폼 바디에서 Action 파라미터를 뽑는다(헤더 기반 경로용). 정확히 1개일
// 때만 채우고, 부재/중복(파라미터 오염)이면 빈 값을 돌려주어 코어가 invalid_shape 로 거르게 한다.
// 첫 값 묵시 채택을 없애, STS 가 실제로 해석하는 값과 로컬 판단이 어긋나지 않게 한다.
func actionFromForm(body string) string {
	form, err := url.ParseQuery(body)
	if err != nil {
		return ""
	}
	if vals := form[queryActionKey]; len(vals) == 1 {
		return vals[0]
	}
	return ""
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
	return parseSignedHeaderList(rest)
}

// parseSignedHeaderList 는 세미콜론으로 구분된 SignedHeaders 목록(예: "host;x-amz-date;
// x-server-binding")을 소문자 집합으로 돌려준다. 비면 nil 이다. 헤더 기반의 Authorization
// SignedHeaders 구간과 presigned 의 X-Amz-SignedHeaders 쿼리가 같은 형식이라 함께 쓴다.
func parseSignedHeaderList(list string) map[string]bool {
	set := make(map[string]bool)
	for _, name := range strings.Split(list, ";") {
		if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
			set[n] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}
