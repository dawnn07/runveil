// Package enrollment resolves the agent's control-plane identity
// (org_id + device_token) from environment variables or an on-disk
// device.json file. Enrollment is optional: a zero Enrollment is a
// valid state and means the agent runs as a pure local proxy.
package enrollment

import "os"

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

// Load resolves enrollment from environment variables, then from
// <dataDir>/device.json, returning a zero Enrollment (with nil error)
// when no source is configured. A malformed or unreadable file is a
// hard error: the operator clearly meant to enroll.
func Load(dataDir string) (Enrollment, error) {
	if orgID, token := os.Getenv("RAILCORE_ORG_ID"), os.Getenv("RAILCORE_DEVICE_TOKEN"); orgID != "" && token != "" {
		return Enrollment{OrgID: orgID, DeviceToken: token}, nil
	}
	return Enrollment{}, nil
}
