package enrollment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoEnvNoFile(t *testing.T) {
	t.Setenv("RAILCORE_ORG_ID", "")
	t.Setenv("RAILCORE_DEVICE_TOKEN", "")
	dir := t.TempDir() // empty directory — no device.json
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if !got.IsZero() {
		t.Errorf("Load: got %+v, want zero Enrollment", got)
	}
}

func TestLoad_EnvWins(t *testing.T) {
	t.Setenv("RAILCORE_ORG_ID", "org_env")
	t.Setenv("RAILCORE_DEVICE_TOKEN", "dt_env")
	dir := t.TempDir()
	// A valid file is present but must be ignored when env is set.
	if err := os.WriteFile(filepath.Join(dir, "device.json"),
		[]byte(`{"org_id":"org_file","device_token":"dt_file"}`), 0600); err != nil {
		t.Fatalf("write device.json: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.OrgID != "org_env" || got.DeviceToken != "dt_env" {
		t.Errorf("Load: got %+v, want {org_env, dt_env}", got)
	}
}
