# samplepython 개발/테스트 표준 진입점. uv 로 환경을 관리하고 한 명령으로 포맷/린트/타입/테스트를
# 돈다. check 가 CI(.github/workflows/ci-python.yml)와 같은 커버리지다.

.PHONY: check sync fmt fmt-check lint type test

# check 는 기본 종합 타깃이다. CI 와 동일한 스위트를 순서대로 돈다.
check: sync fmt-check lint type test

# sync 는 잠긴 의존성(uv.lock)을 설치한다.
sync:
	uv sync

# fmt 는 코드를 포맷한다(개발용, check 에는 포함하지 않음).
fmt:
	uv run ruff format .

# fmt-check 는 미정렬 파일이 있으면 실패한다.
fmt-check:
	uv run ruff format --check .

# lint 는 ruff 린트를 돈다(gofmt+go vet 게이트 대응).
lint:
	uv run ruff check .

# type 은 mypy 타입 검사를 돈다(포트 Protocol 준수 등).
type:
	uv run mypy .

# test 는 단위 + e2e 테스트를 돈다. e2e 안에 presigned 상한 일치 가드
# (test_presign_expiry_bounds_agree)가 있어 표준 명령으로 항상 실행된다.
test:
	uv run pytest
