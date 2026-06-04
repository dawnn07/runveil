package trust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew_ReturnsNonNilInstaller(t *testing.T) {
	i := New()
	if i == nil {
		t.Fatal("New() returned nil")
	}
}

func TestErrNeedsManual_HasMessage(t *testing.T) {
	if !errors.Is(ErrNeedsManual, ErrNeedsManual) {
		t.Fatal("ErrNeedsManual does not satisfy errors.Is on itself")
	}
	if ErrNeedsManual.Error() == "" {
		t.Fatal("ErrNeedsManual has empty message")
	}
}

func TestManualInstructions_NonEmpty(t *testing.T) {
	// Whichever platform we're on, ManualInstructions must return a
	// non-empty string suitable for printing to the user.
	got := ManualInstructions("/some/path/ca.crt")
	if got == "" {
		t.Fatal("ManualInstructions returned empty string")
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "''"},
		{"/usr/local/ca.crt", "'/usr/local/ca.crt'"},
		{"/Users/Some User/ca.crt", "'/Users/Some User/ca.crt'"},
		{"can't.crt", `'can'\''t.crt'`},
	}
	for _, tc := range cases {
		if got := shellQuote(tc.in); got != tc.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestInstall_RealTrustStore actually mutates the running machine's trust
// store. Disabled by default; enable with RUNVEIL_INTEGRATION=1.
//
// The test installs and then uninstalls a freshly generated CA. It fails
// loud if Install returns an error other than ErrNeedsManual.
func TestInstall_RealTrustStore(t *testing.T) {
	if os.Getenv("RUNVEIL_INTEGRATION") != "1" {
		t.Skip("set RUNVEIL_INTEGRATION=1 to enable trust-store integration test")
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := writeTestCA(caPath); err != nil {
		t.Fatalf("write test CA: %v", err)
	}

	i := New()
	t.Cleanup(func() { _ = i.Uninstall(caPath) })

	if err := i.Install(caPath); err != nil && !errors.Is(err, ErrNeedsManual) {
		t.Fatalf("Install: %v", err)
	}
}

// writeTestCA generates a throwaway CA and writes it to path. Defined here
// (not imported from internal/ca) to keep trust a leaf package.
func writeTestCA(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Runveil Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}
