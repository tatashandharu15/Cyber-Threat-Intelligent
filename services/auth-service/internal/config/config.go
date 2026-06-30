// Package config loads the Auth service configuration from the environment.
package config

import (
	"time"

	base "github.com/siberindo/cti/packages/utils/config"
)

// Config is the Auth service configuration.
type Config struct {
	base.Base
	TokenTTL time.Duration
}

// Load reads configuration from the environment.
func Load() Config {
	return Config{
		Base:     base.LoadBase("auth-service"),
		TokenTTL: base.GetDuration("TOKEN_TTL", time.Hour),
	}
}
