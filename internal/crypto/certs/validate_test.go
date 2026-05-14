package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateForSigning_ValidCert(t *testing.T) {
	data, err := os.ReadFile("../../../test/certs/user.crt")
	if err != nil {
		t.Fatalf("failed to read test cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	if err := ValidateForSigning(cert, nil); err != nil {
		t.Fatalf("expected valid cert to pass, got: %v", err)
	}
}

func TestValidateForSigning_ExpiredCert(t *testing.T) {
	cert := generateTestCert(t, 2048, generateCertOpts{
		notBefore: time.Now().Add(-2 * 365 * 24 * time.Hour),
		notAfter:  time.Now().Add(-1 * 365 * 24 * time.Hour),
		keyUsage:  x509.KeyUsageDigitalSignature,
	})
	err := ValidateForSigning(cert, nil)
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
	if !strings.Contains(err.Error(), "certificate has expired") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateForSigning_NotYetValid(t *testing.T) {
	cert := generateTestCert(t, 2048, generateCertOpts{
		notBefore: time.Now().Add(1 * 365 * 24 * time.Hour),
		notAfter:  time.Now().Add(2 * 365 * 24 * time.Hour),
		keyUsage:  x509.KeyUsageDigitalSignature,
	})
	err := ValidateForSigning(cert, nil)
	if err == nil {
		t.Fatal("expected error for not-yet-valid cert")
	}
	if !strings.Contains(err.Error(), "certificate is not yet valid") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateForSigning_NoDigitalSignatureUsage(t *testing.T) {
	cert := generateTestCert(t, 2048, generateCertOpts{
		notBefore: time.Now().Add(-1 * time.Hour),
		notAfter:  time.Now().Add(1 * 365 * 24 * time.Hour),
		keyUsage:  x509.KeyUsageKeyEncipherment,
	})
	err := ValidateForSigning(cert, nil)
	if err == nil {
		t.Fatal("expected error for cert without digital signature key usage")
	}
	if !strings.Contains(err.Error(), "key usage does not permit digital signatures") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateForSigning_SmallRSAKey(t *testing.T) {
	cert := generateTestCert(t, 1024, generateCertOpts{
		notBefore: time.Now().Add(-1 * time.Hour),
		notAfter:  time.Now().Add(1 * 365 * 24 * time.Hour),
		keyUsage:  x509.KeyUsageDigitalSignature,
	})
	err := ValidateForSigning(cert, nil)
	if err == nil {
		t.Fatal("expected error for small RSA key")
	}
	if !strings.Contains(err.Error(), "below minimum 2048 bits") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

type generateCertOpts struct {
	notBefore time.Time
	notAfter  time.Time
	keyUsage  x509.KeyUsage
}

func generateTestCert(t *testing.T, bits int, opts generateCertOpts) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: opts.notBefore,
		NotAfter:  opts.notAfter,
		KeyUsage:  opts.keyUsage,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	return cert
}
