// Command server 는 저장소 README 에서 설명하는 샘플 신뢰 당사자(relying party)
// 서버다. 지금은 graceful 셧다운을 갖춘 HTTP 서버만 구성하며, PoP/STS 위임
// 로직은 이후 단계에서 추가한다.
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
)

const (
	// defaultListenAddr 은 LISTEN_ADDR 이 설정되지 않았을 때 사용한다. README 의
	// 서버 "리슨 주소/포트" 설정 항목에 대응한다.
	defaultListenAddr = ":8080"

	// shutdownTimeout 은 graceful 셧다운 시 처리 중인 요청이 빠질 때까지
	// 기다리는 최대 시간을 제한한다.
	shutdownTimeout = 10 * time.Second
)

func main() {
	// slog 는 서버 전반에서 사용하는 표준 구조화 로거다.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
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

	srv := &http.Server{
		Addr:    addr,
		Handler: inbound.NewRouter(logger),
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
