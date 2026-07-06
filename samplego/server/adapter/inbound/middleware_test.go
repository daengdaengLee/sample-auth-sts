package inbound

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/logging"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	m.Run()
}

// newTestEngine 은 RequestID 미들웨어와 200 을 돌려주는 프로브 핸들러만 붙인
// 엔진을 만든다. request_id 검증은 응답 헤더로 한다.
func newTestEngine() *gin.Engine {
	engine := gin.New()
	engine.Use(RequestID())
	engine.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })
	return engine
}

func doRequest(engine *gin.Engine, header string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if header != "" {
		req.Header.Set(requestIDHeader, header)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// TestRequestID_generatesWhenAbsent 는 헤더가 없을 때 32자 hex ID 를 생성해
// 응답 헤더에 싣는지 확인한다.
func TestRequestID_generatesWhenAbsent(t *testing.T) {
	rec := doRequest(newTestEngine(), "")

	id := rec.Header().Get(requestIDHeader)
	if len(id) != 32 || !isValidRequestID(id) {
		t.Errorf("생성된 request_id 형식이 예상과 다름: %q (len=%d)", id, len(id))
	}
}

// TestRequestID_echoesValid 는 유효한 입력 ID 를 그대로 이어받는지 확인한다.
func TestRequestID_echoesValid(t *testing.T) {
	rec := doRequest(newTestEngine(), "abc-123_XYZ")

	if got := rec.Header().Get(requestIDHeader); got != "abc-123_XYZ" {
		t.Errorf("유효 ID 를 이어받지 못함: %q", got)
	}
}

// TestRequestID_replacesInvalid 는 불량 입력(불량 문자/과길이)이 생성값으로
// 대체되는지 확인한다.
func TestRequestID_replacesInvalid(t *testing.T) {
	cases := map[string]string{
		"공백 포함":  "has space",
		"슬래시 포함": "a/b",
		"과길이":    strings.Repeat("a", maxRequestIDLen+1),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			rec := doRequest(newTestEngine(), in)
			got := rec.Header().Get(requestIDHeader)
			if got == in {
				t.Errorf("불량 입력이 그대로 반영됨: %q", got)
			}
			if len(got) != 32 || !isValidRequestID(got) {
				t.Errorf("대체된 ID 형식이 예상과 다름: %q", got)
			}
		})
	}
}

// TestRequestID_propagatesToLog 는 RequestID 가 심은 request_id 가 context 를 타고
// requestLogger 의 InfoContext 출력까지 도달하는지 end-to-end 로 확인한다.
func TestRequestID_propagatesToLog(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.New(&buf, slog.LevelInfo)

	engine := gin.New()
	engine.Use(RequestID(), requestLogger(logger))
	engine.GET("/probe", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set(requestIDHeader, "trace-xyz")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if out := buf.String(); !strings.Contains(out, "request_id=trace-xyz") {
		t.Errorf("접근 로그에 request_id 가 전파되지 않음: %q", out)
	}
}

// TestIsValidRequestID 는 경계 케이스를 표로 검증한다.
func TestIsValidRequestID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"a", true},
		{"ABYZ09-_", true},
		{strings.Repeat("a", maxRequestIDLen), true},
		{strings.Repeat("a", maxRequestIDLen+1), false},
		{"has space", false},
		{"a/b", false},
		{"a\nb", false},
		{"tab\there", false},
		{"유니코드", false},
	}
	for _, tc := range cases {
		if got := isValidRequestID(tc.in); got != tc.want {
			t.Errorf("isValidRequestID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
