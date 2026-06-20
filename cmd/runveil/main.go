// Package main is the Runveil CLI entrypoint.
//
// Subcommands live in sibling files: proxy.go, init.go, status.go,
// test_policy.go, version.go. helpers.go holds shared utilities.
package main

import (
	"fmt"
	"os"
)

// version is the binary version string. May be overridden at build
// time via -ldflags "-X main.version=$(git describe)".
var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "logs":
		runLogs(os.Args[2:])
	case "enroll":
		runEnroll(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	case "service":
		runService(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "test-policy":
		runTestPolicy(os.Args[2:])
	case "version", "--version", "-v":
		runVersion()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `usage: runveil <command> [flags...]

Commands:
  init           First-run setup: generate CA, install trust, write starter policy.
  logs           Stream the audit log (default: tail last 50, --follow for live).
  enroll         Write control-plane config (URL + device token) for proxy/service.
  proxy          Start the forward HTTPS proxy (foreground).
  service        Install/uninstall the proxy as an always-on background service.
  status         Show config + running-proxy state.
  test-policy    Validate a YAML policy file.
  version        Print binary version.

Run "runveil <command> --help" for command-specific flags.
`)
}
