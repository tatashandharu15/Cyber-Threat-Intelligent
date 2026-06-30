// Package config loads the Takedown service configuration from the environment.
package config

import base "github.com/siberindo/cti/packages/utils/config"

// Config is the Takedown service configuration.
type Config struct {
	base.Base
}

// Load reads configuration from the environment.
func Load() Config {
	return Config{Base: base.LoadBase("takedown-service")}
}
