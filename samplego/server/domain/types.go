package domain

import "time"

// ProofForm 은 증명 형태(SigV4 서명을 어떻게 실었는지)를 가리킨다. 두 형태는 같은
// SignedRequest 로 수렴하되, 형태에 따라 코어의 형태 검증(기대 메서드)과 신선도 판단
// (클라이언트 지정 만료 반영 여부)이 갈린다. 어댑터가 수신 형태를 판별해 채운다.
type ProofForm string

const (
	// FormHeader 는 헤더 기반 서명(Authorization 헤더에 SignedHeaders, POST GetCallerIdentity,
	// 예: Vault)이다. 빈 값(제로값)도 이 형태로 취급해 하위호환을 지킨다.
	FormHeader ProofForm = "header"

	// FormPresigned 는 pre-signed URL 형태(SigV4 쿼리 서명, GET GetCallerIdentity, 클라이언트가
	// X-Amz-Expires 로 만료를 직접 지정, 예: AWS IAM Authenticator)다.
	FormPresigned ProofForm = "presigned"
)

// SignedRequest 는 수신 어댑터가 서명된 GetCallerIdentity 요청을 파싱해 코어로 넘기는
// 값이다. 코어가 로컬 판단에 쓰는 추출 스칼라와, STS 위임에 그대로 쓸 원본 요청을 함께
// 담는다.
type SignedRequest struct {
	// Form 은 증명 형태다(header/presigned). 코어는 형태별 기대 메서드로 형태를 검증하고,
	// presigned 일 때만 아래 Expiry 를 신선도 판단에 반영한다. 빈 값은 header 로 취급한다.
	Form ProofForm

	// BindingValue 는 서명 범위에 포함된 서버 바인딩 헤더 값이다(2단계 검증 대상).
	BindingValue string

	// Method 는 전달 요청의 HTTP 메서드다(3단계 형태 검증용). 코어를 net/http 에서
	// 떼어 두기 위해 문자열로 받는다.
	Method string

	// Action 은 어댑터가 요청 바디/쿼리에서 파싱한 액션 이름이다(3단계 형태 검증용). 코어는
	// 이 값이 GetCallerIdentity 인지 대조한다. 원본 바디 자체는 여기 두지 않고 Original
	// 안에만 두어, 판단용 추출값과 위임용 원본을 분리한다.
	Action string

	// SignedAt 은 요청 서명 시각이다(4단계 신선도 검증용).
	SignedAt time.Time

	// Expiry 는 presigned 에서 클라이언트가 X-Amz-Expires 로 지정한 만료(서명 시각 기준
	// 유효 구간 길이)다. header 형태는 0 이다. 서버는 이 값을 맹신하지 않고 자체 최대 age 와
	// 교집합(min)으로만 신선도에 반영한다(4단계). 즉 클라이언트가 만료를 아무리 길게 잡아도
	// 서버 최대 age 를 넘겨 유효해지지는 않는다.
	Expiry time.Duration

	// Original 은 STS 로 그대로 위임할 원본 서명 요청이다. 코어는 내용을 들여다보지
	// 않고 신원 검증 포트로 넘기기만 한다.
	Original PreservedRequest
}

// PreservedRequest 는 STS 로 재구성 없이 그대로 전달할 원본 서명 요청을 담는 불투명
// 값이다. 코어는 이 안을 해석하지 않는다. 필드 구성은 수신 어댑터와 STS 신원 검증
// 어댑터가 공유해 소유하며, 코어의 기술 비의존을 지키려고 net/http 타입을 쓰지 않는다.
type PreservedRequest struct {
	Method string
	URL    string
	Header map[string][]string
	Body   []byte
}

// Identity 는 STS 가 검증해 돌려준 호출자 신원이다. 코어는 ARN 을 허용 신원 목록과
// 대조한다(7단계).
type Identity struct {
	// ARN 은 허용 목록 대조 대상이다.
	ARN string

	// Account, UserID 는 감사/로그 용도의 부가 정보로, 판단에는 쓰지 않는다.
	Account string
	UserID  string
}

// Credential 은 모든 검증을 통과한 신원에 발급하는 서버 자체 접근 자격이다(8단계).
// 구체 형태(예: JWT)는 자격 발급 어댑터가 정한다.
type Credential struct {
	Token     string
	ExpiresAt time.Time
}
