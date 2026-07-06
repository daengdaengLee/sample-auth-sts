package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestAppendCtx_accumulatesAndCopies 는 속성이 누적되고, 같은 부모에서 파생한
// 두 context 가 서로 간섭하지 않는지 확인한다.
func TestAppendCtx_accumulatesAndCopies(t *testing.T) {
	base := AppendCtx(context.Background(), slog.String("a", "1"))

	// 같은 부모에서 서로 다른 속성을 더한 두 갈래.
	left := AppendCtx(base, slog.String("b", "2"))
	right := AppendCtx(base, slog.String("c", "3"))

	leftAttrs, _ := left.Value(ctxKey{}).([]slog.Attr)
	rightAttrs, _ := right.Value(ctxKey{}).([]slog.Attr)

	if got := attrKeys(leftAttrs); got != "a,b" {
		t.Errorf("left attrs = %q, want %q", got, "a,b")
	}
	if got := attrKeys(rightAttrs); got != "a,c" {
		t.Errorf("right attrs = %q, want %q (파생 간 간섭 발생)", got, "a,c")
	}
}

// TestAppendCtx_doesNotAliasParentBacking 는 여유 capacity 를 가진 부모 슬라이스에서
// 두 갈래로 파생해도 서로의 backing array 를 공유하지 않는지 확인한다. AppendCtx 의
// 명시적 복사가 없으면 두 파생이 같은 배열에 append 하여 뒤엣것이 앞엣것을 덮어쓰므로,
// 이 테스트가 실패한다. (같은 패키지 권한으로 ctxKey 에 직접 심어 상황을 재현한다.)
func TestAppendCtx_doesNotAliasParentBacking(t *testing.T) {
	spare := make([]slog.Attr, 1, 4) // len 1, cap 4 - append 시 재할당 없이 같은 배열을 씀
	spare[0] = slog.String("a", "1")
	parent := context.WithValue(context.Background(), ctxKey{}, spare)

	left := AppendCtx(parent, slog.String("b", "2"))
	right := AppendCtx(parent, slog.String("c", "3"))

	leftAttrs, _ := left.Value(ctxKey{}).([]slog.Attr)
	rightAttrs, _ := right.Value(ctxKey{}).([]slog.Attr)

	if got := attrKeys(leftAttrs); got != "a,b" {
		t.Errorf("left attrs = %q, want %q (backing array aliasing 발생)", got, "a,b")
	}
	if got := attrKeys(rightAttrs); got != "a,c" {
		t.Errorf("right attrs = %q, want %q", got, "a,c")
	}
}

// TestAppendCtx_nilParent 는 nil 부모를 넘겨도 패닉 없이 동작하는지 확인한다.
func TestAppendCtx_nilParent(t *testing.T) {
	//nolint:staticcheck // nil context 방어 동작을 의도적으로 검증한다.
	ctx := AppendCtx(nil, slog.String("a", "1"))
	if attrs, _ := ctx.Value(ctxKey{}).([]slog.Attr); attrKeys(attrs) != "a" {
		t.Errorf("nil 부모에서 속성 누락")
	}
}

// TestContextHandler_attachesCtxAttrs 는 context 에 실린 속성이 로그 출력에
// 자동으로 붙는지 확인한다.
func TestContextHandler_attachesCtxAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)

	ctx := AppendCtx(context.Background(), slog.String("request_id", "abc123"))
	logger.InfoContext(ctx, "hello")

	if out := buf.String(); !strings.Contains(out, "request_id=abc123") {
		t.Errorf("출력에 request_id 누락: %q", out)
	}
}

// TestContextHandler_survivesWith 는 With 로 파생한 로거에서도 context 부착이
// 유지되는지 확인한다. WithAttrs 재래핑이 깨지면 request_id 가 사라져 실패한다.
func TestContextHandler_survivesWith(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)

	derived := logger.With("k", "v")
	ctx := AppendCtx(context.Background(), slog.String("request_id", "abc123"))
	derived.InfoContext(ctx, "hello")

	out := buf.String()
	if !strings.Contains(out, "k=v") {
		t.Errorf("파생 로거의 속성 k=v 누락: %q", out)
	}
	if !strings.Contains(out, "request_id=abc123") {
		t.Errorf("파생 로거에서 context 부착이 깨짐(재래핑 문제): %q", out)
	}
}

// TestContextHandler_survivesWithGroup 는 WithGroup 파생에서도 래퍼가 유지되어
// context 속성이 계속 붙는지 확인한다. 단, context 속성은 로그 시점에 레코드로
// 추가되므로 열린 그룹 안으로 중첩된다(g.request_id). 이는 알려진/의도된 동작이며,
// 그래서 요청 흐름 로거에는 WithGroup 을 쓰지 않는 컨벤션을 둔다(logging.New doc 참고).
func TestContextHandler_survivesWithGroup(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)

	grouped := logger.WithGroup("g")
	ctx := AppendCtx(context.Background(), slog.String("request_id", "abc123"))
	grouped.InfoContext(ctx, "hello")

	if out := buf.String(); !strings.Contains(out, "g.request_id=abc123") {
		t.Errorf("WithGroup 파생에서 context 속성이 그룹 안에 중첩되지 않음(래퍼 깨짐 가능): %q", out)
	}
}

// TestContextHandler_noCtxAttrs 는 속성 없는 context 에서도 정상 출력되는지 확인한다.
func TestContextHandler_noCtxAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, slog.LevelInfo)

	logger.InfoContext(context.Background(), "hello")

	if out := buf.String(); !strings.Contains(out, "msg=hello") {
		t.Errorf("기본 메시지 출력 실패: %q", out)
	}
}

// attrKeys 는 검증을 간단히 하려고 속성 키를 순서대로 이어붙인다.
func attrKeys(attrs []slog.Attr) string {
	keys := make([]string, 0, len(attrs))
	for _, a := range attrs {
		keys = append(keys, a.Key)
	}
	return strings.Join(keys, ",")
}
