package clock

import (
	"testing"
	"time"
)

// TestSystemClock_Now 는 New 가 만든 시계의 Now 가 호출을 감싼 time.Now 구간 안에
// 드는지(단조 sanity) 확인한다. 정확한 값이 아니라 실제 벽시계를 노출하는지만 본다.
func TestSystemClock_Now(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New 가 nil 을 반환함")
	}

	before := time.Now()
	got := c.Now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("Now()=%v 가 [%v, %v] 구간 밖", got, before, after)
	}
}
