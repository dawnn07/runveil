package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"runveil/internal/ca"
	"runveil/internal/trust"
)

const starterPolicyTemplate = `version: 1

rules:
  # Warn on every finding. Edit this file to customize what runveil does
  # with detected secrets and tool-use file paths.
  - name: default-warn
    match: {all: true}
    action: warn

  # --- Examples (uncomment to enable) -----------------------------------

  # Block AWS, GitHub, and Stripe keys.
  # - name: block-cloud-keys
  #   match: {pattern: aws_*}
  #   action: block
  # - name: block-github-tokens
  #   match: {pattern: github_*}
  #   action: block

  # Block agent file access to sensitive paths.
  # - name: block-payments
  #   match: {path: "**/payments/**"}
  #   action: block
  # - name: block-aws-config
  #   match: {path: "**/.aws/**"}
  #   action: block
`

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	force := fs.Bool("force", false, "overwrite existing policy.yaml and re-install CA trust (does NOT regenerate the CA)")
	_ = fs.Parse(args)

	// Step 1: CA — idempotent.
	caDir := filepath.Join(*dataDir, "ca")
	caExists := caCertExists(caDir)
	caInst, err := ca.GenerateOrLoad(caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: CA setup failed: %v\n", err)
		os.Exit(1)
	}
	if caExists {
		fmt.Printf("CA: already present at %s\n", caInst.RootPath())
	} else {
		fmt.Printf("CA: generated at %s\n", caInst.RootPath())
	}

	// Step 2: trust store install (best-effort). RUNVEIL_SKIP_TRUST=1
	// skips it entirely — useful in CI/containers where modifying the OS
	// trust store is impossible or undesirable.
	if os.Getenv("RUNVEIL_SKIP_TRUST") == "1" {
		fmt.Println("trust store: skipped (RUNVEIL_SKIP_TRUST=1)")
	} else {
		installer := trust.New()
		if err := installer.Install(caInst.RootPath()); err != nil {
			if errors.Is(err, trust.ErrNeedsManual) {
				fmt.Printf("trust store: manual install required. Run:\n\n%s\n",
					trust.ManualInstructions(caInst.RootPath()))
			} else {
				fmt.Printf("trust store: install failed: %v\nYou can run manually:\n\n%s\n",
					err, trust.ManualInstructions(caInst.RootPath()))
			}
		} else {
			fmt.Println("trust store: installed")
		}
	}

	// Step 3: starter policy.
	policyPath := filepath.Join(*dataDir, "policy.yaml")
	if err := writeStarterPolicy(policyPath, *force); err != nil {
		fmt.Fprintf(os.Stderr, "init: write policy: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(`
runveil is set up. Start the proxy with:
  runveil proxy
Then configure your AI tool to use http://localhost:9443 as its HTTPS proxy.
`)
}

func writeStarterPolicy(path string, force bool) error {
	if _, err := os.Stat(path); err == nil {
		if !force {
			fmt.Printf("policy: %s already exists; pass --force to overwrite (skipping)\n", path)
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(starterPolicyTemplate), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("policy: wrote starter at %s\n", path)
	return nil
}

func caCertExists(caDir string) bool {
	_, err := os.Stat(filepath.Join(caDir, "ca.crt"))
	return err == nil
}
