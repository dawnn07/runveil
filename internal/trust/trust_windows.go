//go:build windows

package trust

import (
	"fmt"
	"os/exec"
)

func New() Installer { return &windowsInstaller{} }

type windowsInstaller struct{}

func (w *windowsInstaller) Install(caPath string) error {
	// LocalMachine root (requires admin).
	sys := exec.Command("certutil", "-addstore", "-f", "Root", caPath)
	if out, err := sys.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	// Fall back to current user.
	ps := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\CurrentUser\Root | Out-Null`, caPath))
	if out, err := ps.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	return ErrNeedsManual
}

func (w *windowsInstaller) Uninstall(caPath string) error {
	exec.Command("certutil", "-delstore", "Root", caPath).Run()
	exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*Railcore*" } | Remove-Item`)).Run()
	return nil
}

func (w *windowsInstaller) Status(_ string) (bool, string, error) {
	return false, "windows-unknown", nil
}

// ManualInstructions returns shell commands the user can run by hand.
func ManualInstructions(caPath string) string {
	return fmt.Sprintf(`# As Administrator:
certutil -addstore -f Root "%s"
# or, per-user (PowerShell):
Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\CurrentUser\Root
`, caPath, caPath)
}
