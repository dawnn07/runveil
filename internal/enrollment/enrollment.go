// Package enrollment resolves the agent's control-plane identity
// (org_id + device_token) from environment variables or an on-disk
// device.json file. Enrollment is optional: a zero Enrollment is a
// valid state and means the agent runs as a pure local proxy.
package enrollment

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// Enrollment is the agent's control-plane identity, captured once at
// startup. A zero Enrollment means the agent is unenrolled.
type Enrollment struct {
	OrgID       string
	DeviceToken string
}

// IsZero reports whether the Enrollment has no identifying fields set.
func (e Enrollment) IsZero() bool {
	return e.OrgID == "" && e.DeviceToken == ""
}

// fileShape is the wire shape of device.json.
type fileShape struct {
	OrgID       string `json:"org_id"`
	DeviceToken string `json:"device_token"`
}

// Load resolves enrollment from environment variables, then from
// <dataDir>/device.json, returning a zero Enrollment (with nil error)
// when no source is configured. A malformed or unreadable file is a
// hard error: the operator clearly meant to enroll.
func Load(dataDir string) (Enrollment, error) {
	if orgID, token := os.Getenv("RUNVEIL_ORG_ID"), os.Getenv("RUNVEIL_DEVICE_TOKEN"); orgID != "" && token != "" {
		return Enrollment{OrgID: orgID, DeviceToken: token}, nil
	}

	path := filepath.Join(dataDir, "device.json")
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Enrollment{}, nil
		}
		return Enrollment{}, fmt.Errorf("stat %s: %w", path, err)
	}

	// Permission check: 0600 expected; warn if more permissive.
	if mode := info.Mode().Perm(); mode&^0o600 != 0 {
		slog.Default().Warn("device.json permissions are more permissive than 0600",
			"path", path, "mode", fmt.Sprintf("%#o", mode))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Enrollment{}, fmt.Errorf("read %s: %w", path, err)
	}
	var fs fileShape
	if err := json.Unmarshal(data, &fs); err != nil {
		return Enrollment{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if fs.OrgID == "" {
		return Enrollment{}, fmt.Errorf("%s: missing required field org_id", path)
	}
	if fs.DeviceToken == "" {
		return Enrollment{}, fmt.Errorf("%s: missing required field device_token", path)
	}
	return Enrollment(fs), nil
}
