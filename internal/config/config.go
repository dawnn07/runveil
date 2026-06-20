// Package config loads the agent's control-plane configuration from
// <data-dir>/config.json: the control-plane base URL and device token used
// by `runveil proxy` when no explicit flags are given. A missing file is
// not an error (returns a zero Config).
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Config is the on-disk control-plane configuration.
type Config struct {
	ControlPlaneURL string `json:"control_plane_url"`
	DeviceToken     string `json:"device_token"`
}

// PolicyURL derives the policy endpoint from the base URL (empty when unset).
func (c Config) PolicyURL() string { return c.endpoint("/v1/policy") }

// SIEMURL derives the audit endpoint from the base URL (empty when unset).
func (c Config) SIEMURL() string { return c.endpoint("/v1/audit/batch") }

func (c Config) endpoint(path string) string {
	if c.ControlPlaneURL == "" {
		return ""
	}
	return strings.TrimRight(c.ControlPlaneURL, "/") + path
}

// Load reads <dataDir>/config.json. A missing file yields a zero Config and
// nil error; an unreadable or malformed file is an error.
func Load(dataDir string) (Config, error) {
	path := filepath.Join(dataDir, "config.json")
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		slog.Default().Warn("config.json permissions are more permissive than 0600",
			"path", path, "mode", fmt.Sprintf("%#o", mode))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, nil
}
