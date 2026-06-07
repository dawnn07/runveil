//go:build darwin

package trust

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// securityTimeout bounds each `security` invocation. Adding a cert to the
// System keychain triggers an authorization prompt; in a non-interactive
// environment (CI, no admin) the prompt is never answered, so without a
// timeout the call hangs indefinitely. We fail fast instead and fall back
// to manual instructions.
const securityTimeout = 20 * time.Second

func New() Installer { return &darwinInstaller{} }

type darwinInstaller struct{}

func (d *darwinInstaller) Install(caPath string) error {
	// System keychain (admin required; may prompt for authorization).
	if runSecurity("add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", caPath) == nil {
		return nil
	}
	// Fall back to user login keychain.
	if runSecurity("add-trusted-cert", "-r", "trustRoot",
		"-k", homeKeychain(), caPath) == nil {
		return nil
	}
	return ErrNeedsManual
}

func (d *darwinInstaller) Uninstall(caPath string) error {
	_ = runSecurity("remove-trusted-cert", "-d", caPath)
	_ = runSecurity("remove-trusted-cert", caPath)
	return nil
}

// runSecurity runs the macOS `security` tool with a bounded timeout so a
// never-answered authorization prompt cannot hang the process forever.
func runSecurity(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), securityTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "security", args...).Run()
}

func (d *darwinInstaller) Status(_ string) (bool, string, error) {
	return false, "darwin-unknown", nil
}

func homeKeychain() string {
	if home, err := homeDir(); err == nil {
		return home + "/Library/Keychains/login.keychain-db"
	}
	return ""
}

// ManualInstructions returns shell commands the user can run by hand.
func ManualInstructions(caPath string) string {
	q := shellQuote(caPath)
	return fmt.Sprintf(`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s
# or, per-user:
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db %s
`, q, q)
}
