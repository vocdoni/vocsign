package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestValidateForSigning_ValidECDSACert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ECDSA Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateForSigning(cert, nil); err != nil {
		t.Fatalf("ECDSA P-256 cert should pass validation, got: %v", err)
	}
}

func TestCheckRevocation_NoIssuer(t *testing.T) {
	cert := &x509.Certificate{
		OCSPServer: []string{"http://ocsp.example.com"},
	}
	// No issuer => skipped with warning, no error.
	if err := CheckRevocation(cert, nil); err != nil {
		t.Fatalf("expected nil error when no issuer, got: %v", err)
	}
}

func TestCheckRevocation_NoOCSPURL(t *testing.T) {
	cert := &x509.Certificate{
		OCSPServer: []string{},
	}
	issuer := &x509.Certificate{}
	// No OCSP URL => skipped with warning, no error.
	if err := CheckRevocation(cert, issuer); err != nil {
		t.Fatalf("expected nil error when no OCSP URL, got: %v", err)
	}
}

// ocspTestPair generates a CA + leaf certificate pair suitable for OCSP testing.
func ocspTestPair(t *testing.T) (caCert *x509.Certificate, caKey *rsa.PrivateKey, leafCert *x509.Certificate) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
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
	caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// OCSPServer will be set by caller after httptest.NewServer is created.
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return caCert, caKey, leafCert
}

func TestCheckRevocation_OCSPGood(t *testing.T) {
	caCert, caKey, leafCert := ocspTestPair(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := ocsp.CreateResponse(caCert, caCert, ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: leafCert.SerialNumber,
			ThisUpdate:   time.Now().Add(-time.Hour),
			NextUpdate:   time.Now().Add(time.Hour),
		}, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write(resp); err != nil {
			t.Errorf("failed to write OCSP response: %v", err)
		}
	}))
	defer srv.Close()

	leafCert.OCSPServer = []string{srv.URL}

	if err := CheckRevocation(leafCert, caCert); err != nil {
		t.Fatalf("OCSP Good should pass, got: %v", err)
	}
}

func TestCheckRevocation_OCSPRevoked(t *testing.T) {
	caCert, caKey, leafCert := ocspTestPair(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := ocsp.CreateResponse(caCert, caCert, ocsp.Response{
			Status:       ocsp.Revoked,
			SerialNumber: leafCert.SerialNumber,
			RevokedAt:    time.Now().Add(-24 * time.Hour),
			ThisUpdate:   time.Now().Add(-time.Hour),
			NextUpdate:   time.Now().Add(time.Hour),
		}, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write(resp); err != nil {
			t.Errorf("failed to write OCSP response: %v", err)
		}
	}))
	defer srv.Close()

	leafCert.OCSPServer = []string{srv.URL}

	err := CheckRevocation(leafCert, caCert)
	if err == nil {
		t.Fatal("OCSP Revoked should return error")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected 'revoked' in error, got: %v", err)
	}
}

func TestCheckRevocation_OCSPUnknown(t *testing.T) {
	caCert, caKey, leafCert := ocspTestPair(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := ocsp.CreateResponse(caCert, caCert, ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: leafCert.SerialNumber,
			ThisUpdate:   time.Now().Add(-time.Hour),
			NextUpdate:   time.Now().Add(time.Hour),
		}, caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write(resp); err != nil {
			t.Errorf("failed to write OCSP response: %v", err)
		}
	}))
	defer srv.Close()

	leafCert.OCSPServer = []string{srv.URL}

	// Unknown status => warning only, no error.
	if err := CheckRevocation(leafCert, caCert); err != nil {
		t.Fatalf("OCSP Unknown should pass (warn only), got: %v", err)
	}
}
