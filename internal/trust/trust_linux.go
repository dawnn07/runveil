//go:build linux

package trust

import (
	"fmt"
	"os/exec"
)

func New() Installer { return &linuxInstaller{} }

type linuxInstaller struct{}

func (l *linuxInstaller) Install(caPath string) error {
	// Try system store first (requires root).
	if err := tryUpdateCACertificates(caPath); err == nil {
		return nil
	}
	// Fall back to user NSS DB.
	if err := tryNSSInstall(caPath); err == nil {
		return nil
	}
	return ErrNeedsManual
}

func (l *linuxInstaller) Uninstall(caPath string) error {
	_ = tryNSSUninstall(caPath)
	_ = tryUpdateCACertificatesUninstall(caPath)
	return nil
}

func (l *linuxInstaller) Status(caPath string) (bool, string, error) {
	// Best-effort: check both stores. Full verification is integration-test territory.
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		return false, "system-unknown", nil
	}
	return false, "manual", nil
}

func tryUpdateCACertificates(caPath string) error {
	if _, err := exec.LookPath("update-ca-certificates"); err != nil {
		return fmt.Errorf("update-ca-certificates not found: %w", err)
	}
	dest := "/usr/local/share/ca-certificates/railcore.crt"
	cp := exec.Command("cp", caPath, dest)
	if out, err := cp.CombinedOutput(); err != nil {
		return fmt.Errorf("cp: %s: %w", string(out), err)
	}
	upd := exec.Command("update-ca-certificates")
	if out, err := upd.CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates: %s: %w", string(out), err)
	}
	return nil
}

func tryUpdateCACertificatesUninstall(_ string) error {
	dest := "/usr/local/share/ca-certificates/railcore.crt"
	exec.Command("rm", "-f", dest).Run()
	exec.Command("update-ca-certificates", "--fresh").Run()
	return nil
}

func tryNSSInstall(caPath string) error {
	if _, err := exec.LookPath("certutil"); err != nil {
		return fmt.Errorf("certutil not found: %w", err)
	}
	cmd := exec.Command("certutil", "-d", "sql:"+nssDBPath(), "-A", "-t", "C,,", "-n", "railcore", "-i", caPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("certutil: %s: %w", string(out), err)
	}
	return nil
}

func tryNSSUninstall(_ string) error {
	if _, err := exec.LookPath("certutil"); err != nil {
		return nil
	}
	cmd := exec.Command("certutil", "-d", "sql:"+nssDBPath(), "-D", "-n", "railcore")
	_, _ = cmd.CombinedOutput()
	return nil
}

func nssDBPath() string {
	if home, err := homeDir(); err == nil {
		return home + "/.pki/nssdb"
	}
	return "/root/.pki/nssdb"
}

// ManualInstructions returns shell commands the user can run by hand.
func ManualInstructions(caPath string) string {
	q := shellQuote(caPath)
	return fmt.Sprintf(`sudo cp %s /usr/local/share/ca-certificates/railcore.crt && sudo update-ca-certificates
# or, per-user (Firefox/Chrome NSS):
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n railcore -i %s
`, q, q)
}
