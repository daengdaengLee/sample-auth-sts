// Package logging 은 slog 기반 로깅 인프라를 담는다. 전송(HTTP)이나 도메인
// 규칙에 의존하지 않는 횡단 관심사로, 요청 범위 속성을 context 로 흘려보내고
// 로그 시점에 자동으로 부착하는 ContextHandler 패턴을 제공한다.
package logging

import (
	"context"
	"io"
	"log/slog"
)

// ctxKey 는 context 값 충돌을 피하기 위한 비공개 키 타입이다.
type ctxKey struct{}

// AppendCtx 는 기존 context 에 쌓인 속성에 새 속성을 더한 context 를 반환한다.
// 원본 슬라이스를 공유하지 않도록 매번 복사해, 파생 context 간 간섭을 막는다.
func AppendCtx(parent context.Context, attrs ...slog.Attr) context.Context {
	if parent == nil {
		parent = context.Background()
	}

	var existing []slog.Attr
	if v, ok := parent.Value(ctxKey{}).([]slog.Attr); ok {
		existing = v
	}

	merged := make([]slog.Attr, 0, len(existing)+len(attrs))
	merged = append(merged, existing...)
	merged = append(merged, attrs...)

	return context.WithValue(parent, ctxKey{}, merged)
}

// ContextHandler 는 다른 slog.Handler 를 감싸, 로그를 내보내기 직전에 context 에
// 쌓인 속성(예: request_id)을 레코드에 자동으로 부착한다.
type ContextHandler struct {
	slog.Handler
}

// Handle 은 context 의 속성을 레코드에 더한 뒤 내부 핸들러로 위임한다.
func (h ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if attrs, ok := ctx.Value(ctxKey{}).([]slog.Attr); ok {
		r.AddAttrs(attrs...)
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs 는 래퍼를 유지한 채 내부 핸들러를 확장한다. 임베드로 승격된 메서드는
// 내부 핸들러 타입을 반환해 래퍼가 벗겨지므로, 반드시 재래핑해야 파생 로거에서도
// context 부착이 유지된다.
func (h ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return ContextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup 은 WithAttrs 와 같은 이유로 래퍼를 유지한 채 그룹을 연다.
func (h ContextHandler) WithGroup(name string) slog.Handler {
	return ContextHandler{Handler: h.Handler.WithGroup(name)}
}

// New 는 텍스트 핸들러를 ContextHandler 로 감싼 표준 로거를 만든다. 서버 전반에서
// 이 로거를 쓰면 context 에 실린 요청 범위 속성이 모든 로그에 자동으로 붙는다.
func New(w io.Writer, level slog.Leveler) *slog.Logger {
	base := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(ContextHandler{Handler: base})
}
