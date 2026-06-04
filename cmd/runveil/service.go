package main

import (
	"fmt"
	"path/filepath"
)

// serviceConfig holds the resolved values baked into the generated
// service unit and the printed env lines.
type serviceConfig struct {
	Exe     string // absolute path to the runveil binary
	DataDir string
	Port    int
	CAPath  string // <DataDir>/ca/ca.crt
	GOOS    string // runtime.GOOS at install time
	Home    string // user home dir
}

func systemdUnit(cfg serviceConfig) string {
	return fmt.Sprintf(`[Unit]
Description=runveil AI firewall proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s proxy --port %d --data-dir %s
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`, cfg.Exe, cfg.Port, cfg.DataDir)
}

func launchdPlist(cfg serviceConfig) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.runveil.proxy</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>proxy</string>
    <string>--port</string><string>%d</string>
    <string>--data-dir</string><string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`, cfg.Exe, cfg.Port, cfg.DataDir)
}

func serviceEnvLines(cfg serviceConfig) []string {
	return []string{
		fmt.Sprintf("export HTTPS_PROXY=http://127.0.0.1:%d", cfg.Port),
		fmt.Sprintf("export NODE_EXTRA_CA_CERTS=%s", cfg.CAPath),
	}
}

func serviceFilePath(goos, home string) (string, error) {
	switch goos {
	case "linux":
		return filepath.Join(home, ".config", "systemd", "user", "runveil.service"), nil
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", "com.runveil.proxy.plist"), nil
	default:
		return "", fmt.Errorf("unsupported OS %q for automatic service install", goos)
	}
}
