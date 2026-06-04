package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

const (
	leafValidity = 7 * 24 * time.Hour
)

// leafEntry is the in-memory cache value for minted leaf certificates.
type leafEntry struct {
	cert *tls.Certificate
}

// MintLeaf returns a tls.Certificate for the given host, signed by the
// root CA. The same *tls.Certificate is returned for repeated calls for
// the same host (cached for the lifetime of the CA).
func (c *CA) MintLeaf(host string) (*tls.Certificate, error) {
	c.leafMu.Lock()
	defer c.leafMu.Unlock()

	if entry, ok := c.leafCache[host]; ok {
		return entry.cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Runveil"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, &key.PublicKey, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, c.rootCert.Raw},
		PrivateKey:  key,
	}

	c.leafCache[host] = &leafEntry{cert: tlsCert}
	return tlsCert, nil
}
