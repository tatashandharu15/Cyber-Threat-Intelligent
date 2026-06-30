// Package logging configures the structured JSON logger used by every service.
// The output format matches the Architecture Blueprint section 8.3 log schema.
package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

type ctxKey string

const fieldsKey ctxKey = "log_fields"

// New returns a slog.Logger writing JSON to stdout at the given level.
func New(serviceName, level string) *slog.Logger {
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(level),
	})
	return slog.New(h).With(slog.String("service", serviceName))
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithFields stores key/value pairs on the context that ContextAttrs will later
// attach to log records (for example trace_id, tenant_id, request_id).
func WithFields(ctx context.Context, kv map[string]string) context.Context {
	existing, _ := ctx.Value(fieldsKey).(map[string]string)
	merged := make(map[string]string, len(existing)+len(kv))
	for k, v := range existing {
		merged[k] = v
	}
	for k, v := range kv {
		merged[k] = v
	}
	return context.WithValue(ctx, fieldsKey, merged)
}

// ContextAttrs returns slog attributes for any fields stored on the context.
func ContextAttrs(ctx context.Context) []any {
	fields, _ := ctx.Value(fieldsKey).(map[string]string)
	attrs := make([]any, 0, len(fields))
	for k, v := range fields {
		attrs = append(attrs, slog.String(k, v))
	}
	return attrs
}
