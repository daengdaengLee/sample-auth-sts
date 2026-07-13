# samplego 개발/테스트 표준 진입점. 두 모듈(server/client)을 한 명령으로 빌드/검증/테스트한다.
# check 가 CI(.github/workflows/ci.yml)와 같은 커버리지다(빌드 + vet + gofmt + test(+e2e, +race)).
# e2e 는 build tag 로 격리돼 있어 test 타깃이 명시적으로 -tags e2e 로 함께 돌린다. 이 안에
# 크로스모듈 상한 일치 가드(TestPresignExpiryBoundsAgree)가 들어 있어 표준 명령으로 항상 실행된다.

SERVER := samplego/server
CLIENT := samplego/client

# issuer.go 는 이전부터 gofmt 지적이 있는 무관 파일이라 gofmt 게이트에서 예외로 둔다(이번 범위 밖).
IGNORED_FMT := adapter/outbound/issuer/issuer.go

.PHONY: check build vet fmt-check test test-server test-client

# check 는 기본 종합 타깃이다. CI 와 동일한 스위트를 순서대로 돈다.
check: build vet fmt-check test

# build 는 두 모듈을 컴파일한다.
build:
	cd $(SERVER) && go build ./...
	cd $(CLIENT) && go build ./...

# vet 은 두 모듈에 go vet 을 돌린다.
vet:
	cd $(SERVER) && go vet ./...
	cd $(CLIENT) && go vet ./...

# fmt-check 는 gofmt 미정렬 파일이 있으면 실패한다. 서버는 기존 무관 파일(issuer.go)만 관용한다.
fmt-check:
	@out=$$(cd $(SERVER) && gofmt -l . | grep -v '^$(IGNORED_FMT)$$' || true); \
	if [ -n "$$out" ]; then echo "gofmt 필요(server):"; echo "$$out"; exit 1; fi
	@out=$$(cd $(CLIENT) && gofmt -l .); \
	if [ -n "$$out" ]; then echo "gofmt 필요(client):"; echo "$$out"; exit 1; fi

# test 는 두 모듈 단위 테스트(-race)와 클라이언트 크로스모듈 e2e(-tags e2e)를 돈다.
test: test-server test-client

test-server:
	cd $(SERVER) && go test -race ./...

test-client:
	cd $(CLIENT) && go test -race ./...
	cd $(CLIENT) && go test -tags e2e -race ./internal/e2e/...
