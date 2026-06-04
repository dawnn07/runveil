package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

// buildServiceConfig resolves the absolute binary path, home dir, and CA
// path for the current platform.
func buildServiceConfig(dataDir string, port int) (serviceConfig, error) {
	exe, err := os.Executable()
	if err != nil {
		return serviceConfig{}, fmt.Errorf("resolve executable: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return serviceConfig{}, fmt.Errorf("resolve home: %w", err)
	}
	return serviceConfig{
		Exe:     exe,
		DataDir: dataDir,
		Port:    port,
		CAPath:  filepath.Join(dataDir, "ca", "ca.crt"),
		GOOS:    runtime.GOOS,
		Home:    home,
	}, nil
}

// execHostCmd runs an external command, streaming its output, and wraps
// any failure with the command line for context.
func execHostCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func installService(cfg serviceConfig) error {
	path, err := serviceFilePath(cfg.GOOS, cfg.Home)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create unit dir: %w", err)
	}
	var content string
	switch cfg.GOOS {
	case "linux":
		content = systemdUnit(cfg)
	case "darwin":
		content = launchdPlist(cfg)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write unit %s: %w", path, err)
	}
	switch cfg.GOOS {
	case "linux":
		if err := execHostCmd("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		return execHostCmd("systemctl", "--user", "enable", "--now", "runveil.service")
	case "darwin":
		_ = execHostCmd("launchctl", "unload", "-w", path) // best-effort
		return execHostCmd("launchctl", "load", "-w", path)
	}
	return nil
}

func uninstallService(cfg serviceConfig) error {
	path, err := serviceFilePath(cfg.GOOS, cfg.Home)
	if err != nil {
		return err
	}
	switch cfg.GOOS {
	case "linux":
		_ = execHostCmd("systemctl", "--user", "disable", "--now", "runveil.service")
	case "darwin":
		_ = execHostCmd("launchctl", "unload", "-w", path)
	}
	if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return fmt.Errorf("remove unit %s: %w", path, rmErr)
	}
	if cfg.GOOS == "linux" {
		_ = execHostCmd("systemctl", "--user", "daemon-reload")
	}
	return nil
}

func serviceUsage() {
	fmt.Fprint(os.Stderr, `usage: runveil service <install|uninstall> [flags]

  install     Register + start the proxy as a background user service.
  uninstall   Stop + remove the background service.

Flags: --data-dir DIR, --port N
`)
}

// runService dispatches `runveil service ...`.
func runService(args []string) {
	if len(args) == 0 {
		serviceUsage()
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "install":
		runServiceInstall(rest)
	case "uninstall":
		runServiceUninstall(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown service subcommand: %q\n\n", sub)
		serviceUsage()
		os.Exit(2)
	}
}

func runServiceInstall(args []string) {
	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	port := fs.Int("port", defaultPort(), "TCP port the proxy listens on")
	_ = fs.Parse(args)

	cfg, err := buildServiceConfig(*dataDir, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runveil service: %v\n", err)
		os.Exit(1)
	}
	if _, perr := serviceFilePath(cfg.GOOS, cfg.Home); perr != nil {
		fmt.Fprintf(os.Stderr, "runveil service: %v\n", perr)
		fmt.Fprintf(os.Stderr, "Run the proxy manually instead: %s proxy\n", cfg.Exe)
		os.Exit(1)
	}
	if !fileExists(cfg.CAPath) {
		fmt.Fprintln(os.Stderr, "runveil service: CA not found; run 'runveil init' first")
		os.Exit(1)
	}
	if err := installService(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "runveil service: install failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("runveil proxy service installed and started.")
	fmt.Println()
	fmt.Println("Add these lines to your shell profile (e.g. ~/.zshrc), then restart your shell:")
	for _, l := range serviceEnvLines(cfg) {
		fmt.Println("  " + l)
	}
	if cfg.GOOS == "linux" {
		fmt.Println()
		fmt.Println("To keep it running when you're logged out: loginctl enable-linger $USER")
	}
}

func runServiceUninstall(args []string) {
	fs := flag.NewFlagSet("service uninstall", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	port := fs.Int("port", defaultPort(), "TCP port (unused; accepted for symmetry)")
	_ = fs.Parse(args)

	cfg, err := buildServiceConfig(*dataDir, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runveil service: %v\n", err)
		os.Exit(1)
	}
	if err := uninstallService(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "runveil service: uninstall failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("runveil proxy service removed.")
	fmt.Println("You can delete the env lines from your shell profile.")
}
