// Command server 는 저장소 README 에서 설명하는 샘플 신뢰 당사자(relying party)
// 서버다. 조립 루트(buildAuthenticator)에서 공유 설정과 네 개의 아웃바운드 어댑터,
// 도메인 서비스를 조립해 인바운드 라우터에 주입하고, graceful 셧다운을 갖춘 HTTP
// 서버로 서빙한다.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/inbound"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/clock"
	policyconfig "github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/config"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/issuer"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/adapter/outbound/sts"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/domain"
	sharedconfig "github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/config"
	"github.com/daengdaenglee/sample-auth-sts/samplego/server/internal/logging"
)

const (
	// defaultListenAddr 은 LISTEN_ADDR 이 설정되지 않았을 때 사용한다. README 의
	// 서버 "리슨 주소/포트" 설정 항목에 대응한다.
	defaultListenAddr = ":8080"

	// shutdownTimeout 은 graceful 셧다운 시 처리 중인 요청이 빠질 때까지
	// 기다리는 최대 시간을 제한한다.
	shutdownTimeout = 10 * time.Second

	// stsRequestTimeout 은 STS 위임 요청 한 건의 최대 소요 시간이다. STS 어댑터에
	// 주입할 http.Client 에 걸어, 응답이 없을 때 인증 요청이 무한정 매달리지 않게 한다.
	stsRequestTimeout = 10 * time.Second
)

func main() {
	// logging.New 는 텍스트 핸들러를 ContextHandler 로 감싸, context 에 실린 요청
	// 범위 속성(request_id 등)을 모든 로그에 자동으로 붙여주는 표준 로거를 만든다.
	logger := logging.New(os.Stdout, slog.LevelInfo)
	slog.SetDefault(logger)

	if err := run(context.Background(), logger); err != nil {
		logger.Error("server exited with error", slog.Any("error", err))
		os.Exit(1)
	}
}

// run 은 HTTP 서버를 부트스트랩하고 서빙하며, 종료 신호를 받거나 서버 시작에
// 실패할 때까지 블로킹한 뒤 graceful 하게 셧다운한다.
func run(ctx context.Context, logger *slog.Logger) error {
	// graceful 셧다운을 트리거할 수 있도록 SIGINT/SIGTERM 에서 ctx 를 취소한다.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// LISTEN_ADDR 환경변수에서 리슨 주소를 얻고, 없으면 defaultListenAddr 로 폴백한다.
	addr := defaultListenAddr
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		addr = v
	}

	// 조립 루트: 공유 설정을 한 번 로드해 각 어댑터 Load 로 넘기고, 도메인 서비스에 주입한다.
	// 오설정은 각 Load 에서 에러로 드러나므로, 서버가 뜨기 전에 부팅을 실패시킨다.
	auth, verify, err := buildServices(logger)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: inbound.NewRouter(logger, auth, verify),
	}

	// 메인 흐름이 신호 또는 시작/서빙 에러 중 하나를 기다릴 수 있도록
	// 별도 goroutine 에서 서빙한다.
	serveErr := make(chan error, 1)
	go func() {
		logger.Info("server starting", slog.String("addr", addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		// 셧다운을 요청하기 전에 ListenAndServe 가 반환된 경우다.
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}

	logger.Info("server stopped")
	return nil
}

// buildServices 는 헥사고날 조립 루트다. 공유 viper 를 한 번 로드해 아웃바운드 어댑터
// (정책/시계/STS/발급/토큰 검사)를 만들고, 두 도메인 서비스에 주입해 인바운드 포트 두 개
// (/auth 의 Authenticator, /verify 의 TokenVerifier)를 돌려준다. 각 어댑터의 로드/검증 실패
// (정책/발급의 Load, STS 의 NewVerifier -- 유효한 https 엔드포인트 없음)는 그대로 전파해 부팅
// 시점에 오설정을 드러낸다. 시계(clk)와 발급 설정(issuerParams)은 두 경로가 공유한다.
func buildServices(logger *slog.Logger) (domain.Authenticator, domain.TokenVerifier, error) {
	v, err := sharedconfig.Load()
	if err != nil {
		return nil, nil, err
	}

	policy, err := policyconfig.Load(v)
	if err != nil {
		return nil, nil, err
	}

	issuerParams, err := issuer.Load(v)
	if err != nil {
		return nil, nil, err
	}

	clk := clock.New()
	httpClient := &http.Client{Timeout: stsRequestTimeout}

	// NewVerifier 는 허용 엔드포인트를 읽어 Verifier 를 만들고, 정규화를 통과한 유효 엔드포인트가
	// 하나도 없으면(공백뿐 아니라 https 아님 같은 오설정 포함) 에러로 부팅을 실패시킨다.
	// "떠 있지만 모든 /auth 가 401 로 실패하는" 상태를 어댑터 경계에서 막는다.
	verifier, err := sts.NewVerifier(httpClient, v)
	if err != nil {
		return nil, nil, err
	}

	iss := issuer.New(issuerParams)

	// /verify 배선: 발급과 같은 시크릿으로 서명을 재검증하는 검사기와, 발급 설정의 iss/aud
	// 기대값으로 만료/발급자/대상을 판단하는 검증 서비스를 조립한다.
	inspector := issuer.NewInspector(issuerParams)
	tokenVerifier := domain.NewVerifyService(clk, inspector, issuerParams.Issuer, issuerParams.Audience)

	logger.Info("composition root assembled",
		slog.Int("sts_endpoint_count", verifier.AllowedEndpointCount()),
		slog.Duration("sts_timeout", stsRequestTimeout),
	)

	// NewService 의 위치 인자 순서: 정책/시계 -> 신원 검증 -> 자격 발급.
	return domain.NewService(policy, clk, verifier, iss), tokenVerifier, nil
}
