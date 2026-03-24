package cades

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestExtractSignatureValue(t *testing.T) {
	// Generate a test key and certificate.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	// Create a CAdES signature.
	content := []byte("test content for timestamp extraction")
	pkcs7DER, err := SignDetached(context.Background(), crypto.Signer(key), cert, nil, content, SignOpts{
		SigningTime: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Extract the signature value.
	sigValue, err := extractSignatureValue(pkcs7DER)
	if err != nil {
		t.Fatalf("extractSignatureValue failed: %v", err)
	}

	// RSA 2048-bit signatures are 256 bytes.
	if len(sigValue) != 256 {
		t.Fatalf("expected 256-byte RSA signature, got %d bytes", len(sigValue))
	}

	t.Logf("Extracted signature value: %d bytes (from %d byte PKCS#7)", len(sigValue), len(pkcs7DER))
}

func TestExtractSignatureValue_InvalidDER(t *testing.T) {
	_, err := extractSignatureValue([]byte("not a valid DER"))
	if err == nil {
		t.Fatal("expected error for invalid DER, got nil")
	}
}
