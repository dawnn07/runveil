// Package ca generates and persists a local Certificate Authority used to
// MITM HTTPS traffic, and mints per-host leaf certificates signed by it.
//
// ca is a leaf package: it must not import any other internal/ package.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	rootCertFile = "ca.crt"
	rootKeyFile  = "ca.key"
	rootCN       = "Railcore Local CA"
	rootValidity = 10 * 365 * 24 * time.Hour
	rootKeyBits  = 4096
)

// CA holds the root certificate and signing key for the local Railcore CA,
// plus an in-memory cache of minted leaf certificates.
type CA struct {
	dir      string
	rootCert *x509.Certificate
	rootKey  *rsa.PrivateKey

	leafMu    sync.Mutex
	leafCache map[string]*leafEntry
}

// GenerateOrLoad returns a CA backed by ca.crt + ca.key under dir, creating
// them on first use. The directory is created with mode 0700 if missing.
func GenerateOrLoad(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}
	certPath := filepath.Join(dir, rootCertFile)
	keyPath := filepath.Join(dir, rootKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		return loadRoot(dir, certPath, keyPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat ca cert: %w", err)
	}

	return generateRoot(dir, certPath, keyPath)
}

func generateRoot(dir, certPath, keyPath string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, rootKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: rootCN, Organization: []string{"Railcore"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign root: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}
	if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated cert: %w", err)
	}

	return &CA{
		dir:       dir,
		rootCert:  cert,
		rootKey:   key,
		leafCache: make(map[string]*leafEntry),
	}, nil
}

func loadRoot(dir, certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca.crt is not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca.key is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	return &CA{
		dir:       dir,
		rootCert:  cert,
		rootKey:   key,
		leafCache: make(map[string]*leafEntry),
	}, nil
}

// RootPath returns the absolute path of the root certificate file on disk.
func (c *CA) RootPath() string {
	return filepath.Join(c.dir, rootCertFile)
}

// RootCert returns the parsed root certificate. The returned pointer must
// not be mutated.
func (c *CA) RootCert() *x509.Certificate {
	return c.rootCert
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	return n, nil
}
