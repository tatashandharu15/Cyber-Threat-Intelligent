// Package observability wires OpenTelemetry tracing into the shared server. It is
// fully env-driven: with no OTEL_EXPORTER_OTLP_ENDPOINT configured it installs a
// no-op TracerProvider so the platform builds, tests and serves with zero network
// dependency. When an endpoint is set it exports spans over OTLP/HTTP.
package observability

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// serviceName resolves the reported service name from the environment, matching
// the convention used by the metrics/server packages.
func serviceName() string {
	if v := os.Getenv("OTEL_SERVICE_NAME"); v != "" {
		return v
	}
	if v := os.Getenv("SERVICE_NAME"); v != "" {
		return v
	}
	return "cti-service"
}

// InitTracer installs the global TracerProvider and W3C propagators.
//
// If OTEL_EXPORTER_OTLP_ENDPOINT is empty the provider has no exporter (no-op),
// so no collector is required to build or serve. When set, spans are batched and
// exported over OTLP/HTTP (insecure, suitable for local collectors). The returned
// shutdown function flushes and stops the provider.
func InitTracer(ctx context.Context) (func(context.Context) error, error) {
	// Always set a W3C TraceContext + Baggage propagator so trace context flows
	// across services regardless of whether an exporter is configured.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		// No exporter configured: install a plain provider (no batcher) so spans
		// are created but never shipped anywhere. Dev/offline/build safe.
		tp := sdktrace.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return tp.Shutdown, nil
	}

	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithInsecure())
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName()),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}
