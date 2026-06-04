package main

import (
	"slices"
	"strings"
	"testing"
)

func testCfg() serviceConfig {
	return serviceConfig{
		Exe:     "/usr/local/bin/runveil",
		DataDir: "/home/u/.runveil",
		Port:    9443,
		CAPath:  "/home/u/.runveil/ca/ca.crt",
		Home:    "/home/u",
	}
}

func TestSystemdUnit(t *testing.T) {
	got := systemdUnit(testCfg())
	if !strings.Contains(got, "ExecStart=/usr/local/bin/runveil proxy --port 9443 --data-dir /home/u/.runveil") {
		t.Errorf("ExecStart wrong:\n%s", got)
	}
	if !strings.Contains(got, "WantedBy=default.target") {
		t.Errorf("missing WantedBy:\n%s", got)
	}
	if !strings.Contains(got, "Restart=on-failure") {
		t.Errorf("missing Restart:\n%s", got)
	}
}

func TestLaunchdPlist(t *testing.T) {
	got := launchdPlist(testCfg())
	for _, want := range []string{
		"<string>/usr/local/bin/runveil</string>",
		"<string>proxy</string>",
		"<string>--port</string><string>9443</string>",
		"<string>--data-dir</string><string>/home/u/.runveil</string>",
		"<key>KeepAlive</key><true/>",
		"<key>RunAtLoad</key><true/>",
		"<string>com.runveil.proxy</string>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plist missing %q:\n%s", want, got)
		}
	}
}

func TestServiceEnvLines(t *testing.T) {
	got := serviceEnvLines(testCfg())
	want := []string{
		"export HTTPS_PROXY=http://127.0.0.1:9443",
		"export NODE_EXTRA_CA_CERTS=/home/u/.runveil/ca/ca.crt",
	}
	if !slices.Equal(got, want) {
		t.Errorf("env lines = %v, want %v", got, want)
	}
}

func TestServiceFilePath(t *testing.T) {
	linux, err := serviceFilePath("linux", "/home/u")
	if err != nil || linux != "/home/u/.config/systemd/user/runveil.service" {
		t.Errorf("linux path = %q, err = %v", linux, err)
	}
	mac, err := serviceFilePath("darwin", "/Users/u")
	if err != nil || mac != "/Users/u/Library/LaunchAgents/com.runveil.proxy.plist" {
		t.Errorf("darwin path = %q, err = %v", mac, err)
	}
	if _, err := serviceFilePath("windows", "C:/u"); err == nil {
		t.Error("expected error for unsupported OS")
	}
}
