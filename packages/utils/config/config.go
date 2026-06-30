// Package config provides minimal, dependency-free environment configuration
// loading. Every service embeds a Base config and adds its own fields.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Base holds configuration common to all services.
type Base struct {
	ServiceName  string
	Env          string // dev | staging | production
	HTTPPort     int
	LogLevel     string // debug | info | warn | error
	DatabaseURL  string
	KafkaBrokers string // comma-separated host:port list
	JWTSecret    string // HMAC secret for JWT signing/verification (HS256)
	AuditHMACKey string // HMAC key for audit event signatures
}

// LoadBase reads the common configuration from the environment. serviceName is
// used as a fallback for SERVICE_NAME and to derive sensible local defaults.
func LoadBase(serviceName string) Base {
	return Base{
		ServiceName:  GetString("SERVICE_NAME", serviceName),
		Env:          GetString("ENV", "dev"),
		HTTPPort:     GetInt("HTTP_PORT", 8080),
		LogLevel:     GetString("LOG_LEVEL", "info"),
		// Local dev defaults to host port 5433 (see infra/docker/docker-compose.yml),
		// chosen to avoid colliding with a developer's native Postgres on 5432.
		DatabaseURL:  GetString("DATABASE_URL", "postgres://cti:cti@localhost:5433/cti?sslmode=disable"),
		KafkaBrokers: GetString("KAFKA_BROKERS", "localhost:9092"),
		JWTSecret:    GetString("JWT_SECRET", "dev-insecure-jwt-secret-change-me"),
		AuditHMACKey: GetString("AUDIT_HMAC_KEY", "dev-insecure-audit-hmac-key-change-me"),
	}
}

// GetString returns the environment value for key, or def if unset/empty.
func GetString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// GetInt returns the environment value for key parsed as an int, or def.
func GetInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// GetDuration returns the environment value for key parsed as a duration, or def.
func GetDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// GetBool returns the environment value for key parsed as a bool, or def.
func GetBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// MustProductionSecrets returns an error if any insecure default secret is still
// in use while running in a non-dev environment. Services call this at startup.
func (b Base) MustProductionSecrets() error {
	if b.Env == "dev" {
		return nil
	}
	if b.JWTSecret == "" || b.JWTSecret == "dev-insecure-jwt-secret-change-me" {
		return fmt.Errorf("JWT_SECRET must be set to a non-default value in %s", b.Env)
	}
	if b.AuditHMACKey == "" || b.AuditHMACKey == "dev-insecure-audit-hmac-key-change-me" {
		return fmt.Errorf("AUDIT_HMAC_KEY must be set to a non-default value in %s", b.Env)
	}
	return nil
}
