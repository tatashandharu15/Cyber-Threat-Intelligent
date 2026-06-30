// Package server provides a common HTTP server bootstrap with health endpoints,
// standard middleware, and graceful shutdown so every service has identical
// operational behavior.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/siberindo/cti/packages/utils/httpx"
	"github.com/siberindo/cti/packages/utils/metrics"
	"github.com/siberindo/cti/packages/utils/observability"
)

// serviceName resolves the metrics/tracing service label from the environment.
// It is read internally so server.New's signature stays unchanged.
func serviceName() string {
	if v := os.Getenv("OTEL_SERVICE_NAME"); v != "" {
		return v
	}
	if v := os.Getenv("SERVICE_NAME"); v != "" {
		return v
	}
	return "cti-service"
}

// HealthFunc reports component health for readiness checks.
type HealthFunc func(ctx context.Context) error

// Server wraps net/http with lifecycle management.
type Server struct {
	mux    *http.ServeMux
	log    *slog.Logger
	port   int
	checks []HealthFunc
}

// New creates a Server listening on port. Liveness (/healthz) and readiness
// (/ready) endpoints are registered automatically.
func New(port int, log *slog.Logger) *Server {
	s := &Server{mux: http.NewServeMux(), log: log, port: port}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /ready", s.ready)
	// Prometheus exposition endpoint. Like /healthz and /ready it is registered
	// before any auth middleware so it is always reachable.
	s.mux.Handle("GET /metrics", metrics.Handler())
	return s
}

// AddReadinessCheck registers a dependency health check used by /ready.
func (s *Server) AddReadinessCheck(fn HealthFunc) {
	s.checks = append(s.checks, fn)
}

// Mux returns the underlying mux so services can register their routes.
func (s *Server) Mux() *http.ServeMux { return s.mux }

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	for _, c := range s.checks {
		if err := c(r.Context()); err != nil {
			httpx.WriteError(w, r, httpx.NewError("SERVICE_UNAVAILABLE", "dependency not ready: "+err.Error()))
			return
		}
	}
	httpx.WriteJSON(w, r, http.StatusOK, map[string]string{"status": "ready"})
}

// Run starts the server with the standard middleware chain applied and blocks
// until an interrupt/terminate signal triggers graceful shutdown.
func (s *Server) Run() error {
	svc := serviceName()

	// Initialise tracing. With no OTEL_EXPORTER_OTLP_ENDPOINT this is a no-op
	// provider, so it never requires a running collector to build or serve.
	tracerShutdown, err := observability.InitTracer(context.Background())
	if err != nil {
		return fmt.Errorf("init tracer: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tracerShutdown(shutdownCtx)
	}()

	handler := httpx.Chain(s.mux,
		httpx.WithRequestID(),
		httpx.WithRecover(s.log),
		httpx.WithLogging(s.log),
		metrics.Middleware(svc),
	)
	// Wrap the fully chained handler in a server span. Placed outermost so every
	// request is traced; request_id logging still works because WithRequestID is
	// the outermost member of the inner chain.
	var rootHandler http.Handler = otelhttp.NewHandler(handler, "http.server")

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           rootHandler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("http server listening", slog.Int("port", s.port))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-stop:
		s.log.Info("shutdown signal received", slog.String("signal", sig.String()))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	s.log.Info("server stopped cleanly")
	return nil
}
