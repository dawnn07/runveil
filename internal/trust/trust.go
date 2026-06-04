// Package trust installs the Runveil local CA into the operating system's
// trust store. trust is a leaf package: it must not import any other
// internal/ package.
package trust

import "errors"

// ErrNeedsManual is returned from Install when auto-install cannot proceed
// (e.g., insufficient privileges, missing system tools). Callers should
// surface ManualInstructions to the user.
var ErrNeedsManual = errors.New("trust store install requires manual steps")

// Installer is the platform-agnostic trust-store API.
type Installer interface {
	// Install registers caPath as a trusted root in the OS trust store.
	// Returns ErrNeedsManual if the operation requires user action.
	Install(caPath string) error

	// Uninstall removes a previously installed root identified by caPath.
	Uninstall(caPath string) error

	// Status reports whether caPath appears to be trusted, and the method
	// (e.g., "system", "user-nss", "manual") used to verify.
	Status(caPath string) (installed bool, method string, err error)
}
