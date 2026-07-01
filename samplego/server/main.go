// Command server is the sample trusted-party (relying party) server described in
// the repository README. For now it only wires up an HTTP server with graceful
// shutdown; the PoP/STS delegation logic is added in later steps.
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

	"github.com/gin-gonic/gin"
)

const (
	// defaultListenAddr is used when LISTEN_ADDR is not set. It maps to the
	// server "listen address/port" configuration item in the README.
	defaultListenAddr = ":8080"

	// shutdownTimeout bounds how long we wait for in-flight requests to drain
	// during graceful shutdown.
	shutdownTimeout = 10 * time.Second
)

func main() {
	logger := newLogger()
	slog.SetDefault(logger)

	if err := run(context.Background(), logger); err != nil {
		logger.Error("server exited with error", slog.Any("error", err))
		os.Exit(1)
	}
}

// run bootstraps and serves the HTTP server, blocking until a termination
// signal is received or the server fails to start, then shuts down gracefully.
func run(ctx context.Context, logger *slog.Logger) error {
	// Cancel ctx on SIGINT/SIGTERM so we can trigger a graceful shutdown.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := listenAddr()

	srv := &http.Server{
		Addr:    addr,
		Handler: newRouter(logger),
	}

	// Serve in a goroutine so the main flow can wait on either a signal or a
	// startup/serve error.
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
		// ListenAndServe returned before any shutdown was requested.
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

// newLogger builds the application logger. slog is the standard structured
// logger used throughout the server.
func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// listenAddr resolves the server listen address from the LISTEN_ADDR
// environment variable, falling back to defaultListenAddr.
func listenAddr() string {
	if addr := os.Getenv("LISTEN_ADDR"); addr != "" {
		return addr
	}
	return defaultListenAddr
}

// newRouter builds the gin engine with a slog-based request logger, panic
// recovery, and the health-check route.
func newRouter(logger *slog.Logger) *gin.Engine {
	engine := gin.New()
	engine.Use(requestLogger(logger), gin.Recovery())

	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	return engine
}

// requestLogger logs one line per request through slog, keeping log output
// consistent with the rest of the server.
func requestLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		logger.Info("request",
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("latency", time.Since(start)),
			slog.String("client_ip", c.ClientIP()),
		)
	}
}
