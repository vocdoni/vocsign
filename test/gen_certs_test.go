package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vocdoni/gofirma/vocsign/internal/crypto/cades"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestGenerateIDCatCertWithAllFields generates a PKCS#12 test certificate
// mimicking an IDCat certificate with additional fields:
// - Subject Directory Attributes with dateOfBirth
//
// Output: test/certs/idcat_full_nopass.p12
func TestGenerateIDCatCertWithAllFields(t *testing.T) {
	if os.Getenv("GENERATE_TEST_CERTS") == "" {
		t.Skip("set GENERATE_TEST_CERTS=1 to regenerate test certificates")
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"ES"},
			Organization: []string{"CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA"},
			CommonName:   "EC-Ciutadania",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	sdaExtValue := buildSubjectDirectoryAttributes(t, "19900515")

	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Mirror the exact Subject DN structure of real EC-Ciutadania (IDCat)
	// certificates: serialNumber + GN + SN + CN, no Country or OU fields.
	// ExtraNames (not Names) must be used — Names is only populated during
	// parsing and is ignored when marshaling.
	userTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: "IDCES-12345678Z"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "ALBA"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "TESTER DEMO"},
			},
			CommonName: "ALBA TESTER DEMO - DNI 12345678Z",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageEmailProtection,
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 9},
				Value: sdaExtValue,
			},
		},
	}

	userCertDER, err := x509.CreateCertificate(rand.Reader, userTemplate, caCert, &userKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	userCert, err := x509.ParseCertificate(userCertDER)
	if err != nil {
		t.Fatal(err)
	}

	p12Data, err := gopkcs12.LegacyRC2.Encode(userKey, userCert, []*x509.Certificate{caCert}, "")
	if err != nil {
		t.Fatal(err)
	}

	outPath := "certs/idcat_full_nopass.p12"
	if err := os.WriteFile(outPath, p12Data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("Generated %s (%d bytes)", outPath, len(p12Data))

	// Also output the CA certificate as PEM so it can be loaded into the
	// webapp trust store via EXTRA_TRUST_ROOTS for near-production testing.
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caOutPath := "certs/ec-ciutadania-test-ca.pem"
	if err := os.WriteFile(caOutPath, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("Generated %s", caOutPath)
}

// TestGenerateCAdESFixtures generates CAdES signature fixtures for the
// webapp TypeScript tests.
//
// Output: webapp/apps/api/src/__fixtures__/
//   - signature.der.base64 — base64-encoded PKCS#7 DER
//   - content.base64 — base64-encoded ILP XML
//   - signer.pem — signer certificate PEM
func TestGenerateCAdESFixtures(t *testing.T) {
	if os.Getenv("GENERATE_TEST_CERTS") == "" {
		t.Skip("set GENERATE_TEST_CERTS=1 to regenerate CAdES test fixtures")
	}

	// 1. Generate CA key pair.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Fixture CA", Country: []string{"ES"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Generate signer key pair.
	signerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "FIXTURE SIGNER - DNI 12345678Z",
			Country:    []string{"ES"},
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "FIXTURE"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "SIGNER"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: "IDCES-12345678Z"},
			},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, caCert, &signerKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	signerCert, err := x509.ParseCertificate(signerDER)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Create ILP XML content.
	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<SignaturaILP versio="1.0">
  <ILP>
    <Titol>Test Proposal</Titol>
    <Codi>fixture-req-001</Codi>
  </ILP>
  <Signant>
    <Nom>FIXTURE</Nom>
    <Cognom1>SIGNER</Cognom1>
    <Cognom2></Cognom2>
    <DataNaixement>1990-01-01</DataNaixement>
    <TipusIdentificador>DNI</TipusIdentificador>
    <NumeroIdentificador>12345678Z</NumeroIdentificador>
  </Signant>
</SignaturaILP>`)

	// 4. Sign with CAdES detached.
	sig, err := cades.SignDetached(context.Background(), signerKey, signerCert, []*x509.Certificate{caCert}, content, cades.SignOpts{
		SigningTime: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 5. Write fixtures.
	outDir := filepath.Join("..", "webapp", "apps", "api", "src", "__fixtures__")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(outDir, "signature.der.base64"), []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "content.base64"), []byte(base64.StdEncoding.EncodeToString(content)), 0o644); err != nil {
		t.Fatal(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signerCert.Raw})
	if err := os.WriteFile(filepath.Join(outDir, "signer.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Logf("CAdES fixtures written to %s", outDir)
	t.Logf("  signature: %d bytes (base64)", len(sig))
	t.Logf("  content:   %d bytes", len(content))
	t.Logf("  signer:    %s", signerCert.Subject.CommonName)
}

func buildSubjectDirectoryAttributes(t *testing.T, dateYYYYMMDD string) []byte {
	t.Helper()
	dobOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 1}
	genTime := dateYYYYMMDD + "000000Z"

	gtBytes, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   24,
		Bytes: []byte(genTime),
	})
	if err != nil {
		t.Fatal(err)
	}

	setBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        17,
		IsCompound: true,
		Bytes:      gtBytes,
	})
	if err != nil {
		t.Fatal(err)
	}

	type attribute struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	attrs := []attribute{{
		Type:  dobOID,
		Value: asn1.RawValue{FullBytes: setBytes},
	}}

	result, err := asn1.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
