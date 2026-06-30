// Package metrics provides Prometheus instrumentation that every service
// inherits through the shared HTTP server. It exposes a /metrics handler and an
// HTTP middleware that records request counts and latencies, so no per-service
// code is required.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/siberindo/cti/packages/utils/httpx"
)

var (
	// requestsTotal counts HTTP requests partitioned by service, method, route
	// and response status code.
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests handled.",
		},
		[]string{"service", "method", "route", "code"},
	)

	// requestDuration observes HTTP request latencies (default buckets)
	// partitioned by service, method and route.
	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"service", "method", "route"},
	)
)

// Handler returns the Prometheus exposition handler for the default registry.
func Handler() http.Handler {
	return promhttp.Handler()
}

// statusRecorder captures the response status code while remaining transparent
// to the wrapped handler.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Middleware records request count and duration metrics for every request,
// labelling them with the given service name. The route label uses the Go 1.22
// ServeMux pattern when available, falling back to the request path.
func Middleware(service string) httpx.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			route := r.Pattern
			if route == "" {
				route = r.URL.Path
			}
			requestDuration.WithLabelValues(service, r.Method, route).Observe(time.Since(start).Seconds())
			requestsTotal.WithLabelValues(service, r.Method, route, strconv.Itoa(rec.status)).Inc()
		})
	}
}
