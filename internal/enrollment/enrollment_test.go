package enrollment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoEnvNoFile(t *testing.T) {
	t.Setenv("RUNVEIL_ORG_ID", "")
	t.Setenv("RUNVEIL_DEVICE_TOKEN", "")
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
	t.Setenv("RUNVEIL_ORG_ID", "org_env")
	t.Setenv("RUNVEIL_DEVICE_TOKEN", "dt_env")
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

func TestLoad_FileFallback(t *testing.T) {
	t.Setenv("RUNVEIL_ORG_ID", "")
	t.Setenv("RUNVEIL_DEVICE_TOKEN", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device.json"),
		[]byte(`{"org_id":"org_f","device_token":"dt_f"}`), 0600); err != nil {
		t.Fatalf("write device.json: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.OrgID != "org_f" || got.DeviceToken != "dt_f" {
		t.Errorf("Load: got %+v, want {org_f, dt_f}", got)
	}
}

func TestLoad_HalfSetEnvFallsThrough(t *testing.T) {
	t.Setenv("RUNVEIL_ORG_ID", "org_env")
	t.Setenv("RUNVEIL_DEVICE_TOKEN", "") // only one half — must fall through
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device.json"),
		[]byte(`{"org_id":"org_f","device_token":"dt_f"}`), 0600); err != nil {
		t.Fatalf("write device.json: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.OrgID != "org_f" || got.DeviceToken != "dt_f" {
		t.Errorf("Load: got %+v, want file values (env half-set must fall through)", got)
	}
}

func TestLoad_MalformedFileErrors(t *testing.T) {
	t.Setenv("RUNVEIL_ORG_ID", "")
	t.Setenv("RUNVEIL_DEVICE_TOKEN", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device.json"),
		[]byte(`{not valid json`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load: want error for malformed JSON, got nil")
	}
}

func TestLoad_FileMissingFieldErrors(t *testing.T) {
	t.Setenv("RUNVEIL_ORG_ID", "")
	t.Setenv("RUNVEIL_DEVICE_TOKEN", "")
	dir := t.TempDir()
	// device_token is missing.
	if err := os.WriteFile(filepath.Join(dir, "device.json"),
		[]byte(`{"org_id":"org_f"}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load: want error for missing device_token, got nil")
	}
}
