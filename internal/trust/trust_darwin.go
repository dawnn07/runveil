//go:build darwin

package trust

import (
	"fmt"
	"os/exec"
)

func New() Installer { return &darwinInstaller{} }

type darwinInstaller struct{}

func (d *darwinInstaller) Install(caPath string) error {
	// System keychain (admin required).
	sys := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", caPath)
	if out, err := sys.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	// Fall back to user login keychain.
	usr := exec.Command("security", "add-trusted-cert", "-r", "trustRoot",
		"-k", homeKeychain(), caPath)
	if out, err := usr.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	return ErrNeedsManual
}

func (d *darwinInstaller) Uninstall(caPath string) error {
	exec.Command("security", "remove-trusted-cert", "-d", caPath).Run()
	exec.Command("security", "remove-trusted-cert", caPath).Run()
	return nil
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
