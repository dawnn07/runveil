package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"runveil/internal/config"
)

// writeConfig writes <dataDir>/config.json at 0600.
func writeConfig(dataDir string, c config.Config) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, "config.json"), data, 0o600)
}

// verifyEnrollment does a best-effort GET <base>/v1/policy with the token,
// returning nil on 200/304 and an error otherwise.
func verifyEnrollment(base, token string) error {
	c := config.Config{ControlPlaneURL: base}
	req, err := http.NewRequest(http.MethodGet, c.PolicyURL(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	return fmt.Errorf("control plane returned %d", resp.StatusCode)
}

// runEnroll handles `runveil enroll`.
func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	url := fs.String("url", "", "control-plane base URL (e.g. https://cloud.runveil.io)")
	token := fs.String("token", "", "device token from the dashboard (dt_...)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	noVerify := fs.Bool("no-verify", false, "skip the connectivity check")
	_ = fs.Parse(args)

	if *url == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "runveil enroll: --url and --token are required")
		os.Exit(2)
	}

	if err := writeConfig(*dataDir, config.Config{ControlPlaneURL: *url, DeviceToken: *token}); err != nil {
		fmt.Fprintf(os.Stderr, "runveil enroll: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", filepath.Join(*dataDir, "config.json"))

	if !*noVerify {
		if err := verifyEnrollment(*url, *token); err != nil {
			fmt.Fprintf(os.Stderr, "warning: connectivity check failed: %v\n", err)
		} else {
			fmt.Println("control plane reachable; token accepted.")
		}
	}
	fmt.Println("Next: run 'runveil init' (if not done), then 'runveil service install' or 'runveil proxy'.")
}
