package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_MissingIsZero(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.ControlPlaneURL != "" || c.DeviceToken != "" {
		t.Fatalf("want zero, got %+v", c)
	}
	if c.PolicyURL() != "" || c.SIEMURL() != "" {
		t.Fatalf("zero config should derive empty URLs")
	}
}

func TestLoad_ParsesAndDerives(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, `{"control_plane_url":"https://cp.example.com/","device_token":"dt_x"}`)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.DeviceToken != "dt_x" {
		t.Fatalf("token: %q", c.DeviceToken)
	}
	if got := c.PolicyURL(); got != "https://cp.example.com/v1/policy" {
		t.Fatalf("policy url: %q", got)
	}
	if got := c.SIEMURL(); got != "https://cp.example.com/v1/audit/batch" {
		t.Fatalf("siem url: %q", got)
	}
}

func TestLoad_MalformedErrors(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, `{not json`)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error on malformed json")
	}
}
