// Package clock 는 README 헥사고날 설계의 "시계 어댑터(아웃바운드 어댑터)"다.
// 도메인 코어의 Clock 아웃바운드 포트를 시스템 시계로 구현해, 코어의 신선도/최대
// age 판단에 실제 현재 시각을 제공한다. 테스트에서 시각을 고정할 수 있도록 코어는
// 포트에만 의존하고, 실제 time.Now 의존은 이 어댑터에 가둔다.
package clock

import (
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
)

// systemClock 은 프로세스가 도는 호스트의 벽시계(time.Now)를 그대로 노출하는 Clock
// 구현이다. 상태가 없으므로 빈 구조체로 둔다.
type systemClock struct{}

// Now 는 현재 시각을 돌려준다.
func (systemClock) Now() time.Time {
	return time.Now()
}

// New 는 시스템 시계로 동작하는 Clock 을 만든다. main 의 조립 지점에서 도메인
// Service 에 주입한다.
func New() domain.Clock {
	return systemClock{}
}

// 컴파일 타임에 systemClock 이 아웃바운드 포트를 만족하는지 확인한다.
var _ domain.Clock = systemClock{}
