// Package config loads the Collection Adapter Manager configuration from the
// environment.
package config

import base "github.com/siberindo/cti/packages/utils/config"

// Config is the Collection Adapter Manager configuration.
type Config struct {
	base.Base
}

// Load reads configuration from the environment.
func Load() Config {
	return Config{Base: base.LoadBase("collection-adapter-manager")}
}
