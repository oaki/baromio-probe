// Package config loads the Probe's runtime configuration from environment
// variables. There is no config file: a container or systemd unit sets these
// directly (docs/design-plans/2026-10-05-private-probe.md §7.4).
package config

import (
	"fmt"
	"os"
	"strings"
)

// Config is the Probe's environment-derived runtime configuration.
type Config struct {
	// EnrollToken is the one-time Enrollment Token. Required only on first
	// start, before an identity exists in DataDir; ignored afterwards.
	EnrollToken string

	// Allow is the raw BAROMIO_ALLOW value: a comma-separated list of CIDR
	// ranges, bare hosts, or host:port pairs a monitor's target must fall
	// within before the Probe will check it.
	Allow string

	// URL is the Baromio API base, e.g. https://baromio.io. Defaults to the
	// production API when unset.
	URL string

	// DataDir holds the Probe's identity (ed25519 key pair + probe id) and
	// its result buffer. Must persist across restarts or the Probe loses its
	// enrollment and needs a fresh Enrollment Token.
	DataDir string
}

const defaultURL = "https://baromio.io"

// Load reads the Probe's configuration from the process environment.
func Load() (Config, error) {
	cfg := Config{
		EnrollToken: os.Getenv("BAROMIO_ENROLL_TOKEN"),
		Allow:       os.Getenv("BAROMIO_ALLOW"),
		URL:         strings.TrimRight(envOr("BAROMIO_URL", defaultURL), "/"),
		DataDir:     envOr("BAROMIO_DATA_DIR", "/var/lib/baromio-probe"),
	}

	if cfg.Allow == "" {
		return Config{}, fmt.Errorf("BAROMIO_ALLOW is required: at least one CIDR range, host, or host:port must be allowed")
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
