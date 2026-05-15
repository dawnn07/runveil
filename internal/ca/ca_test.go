package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateOrLoad_CreatesFreshRoot(t *testing.T) {
	dir := t.TempDir()
	c, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}
	if c == nil {
		t.Fatal("CA is nil")
	}

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}

	// Skip permission assertions on Windows; POSIX modes are not meaningful.
	if runtime.GOOS != "windows" {
		keyInfo, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("stat key: %v", err)
		}
		if mode := keyInfo.Mode().Perm(); mode != 0o600 {
			t.Fatalf("key perm = %o, want 0600", mode)
		}
	}

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("ca.crt is not PEM-encoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("root cert must have IsCA=true")
	}
	if cert.Subject.CommonName != "Railcore Local CA" {
		t.Fatalf("CN = %q, want %q", cert.Subject.CommonName, "Railcore Local CA")
	}
}

func TestGenerateOrLoad_ReloadsExistingRoot(t *testing.T) {
	dir := t.TempDir()
	c1, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	c2, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !c1.rootCert.Equal(c2.rootCert) {
		t.Fatal("second call returned a different cert; expected identical reload")
	}
}

func TestRootPath_PointsAtCertFile(t *testing.T) {
	dir := t.TempDir()
	c, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}
	if got, want := c.RootPath(), filepath.Join(dir, "ca.crt"); got != want {
		t.Fatalf("RootPath = %q, want %q", got, want)
	}
}

func TestMintLeaf_ContainsHostSANAndChainsToRoot(t *testing.T) {
	dir := t.TempDir()
	c, err := GenerateOrLoad(dir)
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}

	tlsCert, err := c.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("tls.Certificate.Certificate is empty")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	found := false
	for _, san := range leaf.DNSNames {
		if san == "api.openai.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("leaf DNS SANs = %v, want to contain api.openai.com", leaf.DNSNames)
	}

	pool := x509.NewCertPool()
	pool.AddCert(c.rootCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("leaf did not chain to root: %v", err)
	}
}

func TestMintLeaf_CachesByHost(t *testing.T) {
	c, err := GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}
	a, err := c.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatalf("first MintLeaf: %v", err)
	}
	b, err := c.MintLeaf("api.openai.com")
	if err != nil {
		t.Fatalf("second MintLeaf: %v", err)
	}
	// Pointer equality: same cached cert returned both times.
	if a != b {
		t.Fatal("expected same *tls.Certificate from cache; got different pointers")
	}
}

func TestMintLeaf_ConcurrentSameHostReturnsSingleCert(t *testing.T) {
	c, err := GenerateOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateOrLoad: %v", err)
	}
	const n = 32
	results := make(chan any, n)
	for i := 0; i < n; i++ {
		go func() {
			cert, err := c.MintLeaf("api.openai.com")
			if err != nil {
				results <- err
				return
			}
			results <- cert
		}()
	}
	var first any
	for i := 0; i < n; i++ {
		r := <-results
		if err, ok := r.(error); ok {
			t.Fatalf("MintLeaf error: %v", err)
		}
		if first == nil {
			first = r
			continue
		}
		if r != first {
			t.Fatal("concurrent MintLeaf for same host returned different certs")
		}
	}
}
