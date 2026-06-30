// Package config loads the Reporting service configuration from the environment.
package config

import base "github.com/siberindo/cti/packages/utils/config"

// Config is the Reporting service configuration.
type Config struct {
	base.Base
}

// Load reads configuration from the environment.
func Load() Config {
	return Config{Base: base.LoadBase("reporting-service")}
}
