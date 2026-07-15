"""설정 어댑터(정책). 공유 설정에서 서버 정책 값을 읽어 도메인 Policy 포트를 구현한다.

코어가 실제로 판단에 쓰는 값(바인딩 기대값, 최대 age, 허용 ARN 목록)만 노출한다. STS 엔드포인트
허용 목록/리전은 코어가 쓰지 않고 STS 신원 검증 어댑터가 경계에서 강제하므로 여기 두지 않는다
(인터페이스 분리).
"""

from __future__ import annotations

from datetime import timedelta

from server.domain.ports import Policy
from server.internal.config import PolicySettings
from server.internal.duration import DurationError, parse_duration

# policy.request_max_age 가 설정되지 않았을 때 쓰는 기본 최대 age.
_DEFAULT_MAX_AGE = timedelta(minutes=5)


class PolicyConfig:
    """공유 설정에서 로드한 서버 정책 값을 담고 도메인 Policy 포트를 구현한다. 값은 불변으로
    다루며 접근은 메서드로만 한다.
    """

    def __init__(self, binding: str, max_age: timedelta, allowed_arns: frozenset[str]) -> None:
        self._binding = binding
        self._max_age = max_age
        self._allowed_arns = allowed_arns

    def expected_binding(self) -> str:
        """이 서버만 받아들이는 고유 바인딩 기대값이다(2단계)."""

        return self._binding

    def max_age(self) -> timedelta:
        """받아들일 서명 요청의 최대 age 다(4단계)."""

        return self._max_age

    def is_allowed_arn(self, arn: str) -> bool:
        """STS 가 돌려준 ARN 이 허용 신원 목록에 드는지 대조한다(7단계)."""

        return arn in self._allowed_arns


def _parse_arns(raw: str) -> frozenset[str]:
    """쉼표로 구분한 ARN 목록 문자열을 집합으로 만든다. 각 항목의 앞뒤 공백을 다듬고 빈 항목은
    버린다. 빈 문자열이면 빈 집합을 돌려준다(전부 거부).
    """

    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def load(settings: PolicySettings) -> PolicyConfig:
    """공유 설정에서 정책 값을 읽어 PolicyConfig 를 만든다. policy.binding_value 가 비었거나
    policy.request_max_age 형식이 잘못되면 예외를 던져 부팅 시점에 오설정을 빨리 드러낸다.
    """

    binding = settings.binding_value
    if binding == "":
        raise ValueError("설정 policy.binding_value 가 비어 있음(서버별 고유 바인딩 기대값 필요)")

    max_age = _DEFAULT_MAX_AGE
    raw = settings.request_max_age
    if raw != "":
        try:
            max_age = parse_duration(raw)
        except DurationError as e:
            raise ValueError(f"설정 policy.request_max_age 파싱 실패({raw!r}): {e}") from e
    if max_age <= timedelta(0):
        raise ValueError(
            f"설정 policy.request_max_age 는 양수여야 함(현재 {max_age}): "
            "0 이하면 모든 요청이 거부됨"
        )

    return PolicyConfig(
        binding=binding,
        max_age=max_age,
        allowed_arns=_parse_arns(settings.allowed_arns),
    )


def _conforms(c: PolicyConfig) -> Policy:
    """컴파일타임 포트 준수 확인: PolicyConfig 가 Policy 를 만족하는지 mypy 가 검사한다."""

    return c
