package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteStarterPolicy_FreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := writeStarterPolicy(path, false); err != nil {
		t.Fatalf("writeStarterPolicy: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "default-warn") {
		t.Errorf("starter policy missing default-warn rule; got %s", string(data))
	}
	info, _ := os.Stat(path)
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("perms = %o, want 0644", mode)
	}
}

func TestWriteStarterPolicy_ExistingFileWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	original := []byte("custom content")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeStarterPolicy(path, false); err != nil {
		t.Errorf("writeStarterPolicy returned error: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Errorf("file was overwritten without --force; got %q", string(got))
	}
}

func TestWriteStarterPolicy_ExistingFileWithForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	original := []byte("custom content")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeStarterPolicy(path, true); err != nil {
		t.Errorf("writeStarterPolicy with force: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) == string(original) {
		t.Errorf("file was not overwritten despite --force")
	}
	if !strings.Contains(string(got), "default-warn") {
		t.Errorf("overwritten content should be the starter template")
	}
}
