package enrollment

import (
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
