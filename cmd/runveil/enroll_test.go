package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"runveil/internal/config"
)

func TestWriteConfig_WritesO600(t *testing.T) {
	dir := t.TempDir()
	if err := writeConfig(dir, config.Config{ControlPlaneURL: "http://cp", DeviceToken: "dt_x"}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.json")
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
	}
	var c config.Config
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.ControlPlaneURL != "http://cp" || c.DeviceToken != "dt_x" {
		t.Fatalf("round-trip: %+v", c)
	}
}

func TestVerifyEnrollment_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "dt_x" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := verifyEnrollment(srv.URL, "dt_x"); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestVerifyEnrollment_BadToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if err := verifyEnrollment(srv.URL, "wrong"); err == nil {
		t.Fatal("expected error on 401")
	}
}
