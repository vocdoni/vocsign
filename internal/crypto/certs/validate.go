package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ValidateForSigning checks that a certificate is suitable for producing
// a legally-binding digital signature. It verifies time validity, key usage,
// key type, and minimum key size. If issuerCerts is provided, the first
// certificate is used to perform OCSP revocation checking.
func ValidateForSigning(cert *x509.Certificate, issuerCerts []*x509.Certificate) error {
	now := time.Now()

	// 1. Time validity
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (notBefore: %s)", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (notAfter: %s)", cert.NotAfter.Format(time.RFC3339))
	}

	// 2. Key usage
	if cert.KeyUsage != 0 {
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("certificate key usage does not permit digital signatures")
		}
	}

	// 3. Key type and 4. RSA minimum key size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key size %d is below minimum 2048 bits", pub.N.BitLen())
		}
	case *ecdsa.PublicKey:
		// ECDSA is supported, no minimum size requirement specified.
	default:
		return fmt.Errorf("unsupported key type: %T", cert.PublicKey)
	}

	// 5. OCSP revocation check
	var issuer *x509.Certificate
	if len(issuerCerts) > 0 {
		issuer = issuerCerts[0]
	}
	if err := CheckRevocation(cert, issuer); err != nil {
		return err
	}

	return nil
}

// CheckRevocation performs OCSP certificate revocation checking. It contacts
// the OCSP responder indicated in the certificate and verifies that the
// certificate has not been revoked. The issuer certificate is required to
// construct the OCSP request; if issuer is nil, checking is skipped with a
// warning.
func CheckRevocation(cert *x509.Certificate, issuer *x509.Certificate) error {
	if issuer == nil {
		log.Printf("WARNING: no issuer certificate available, skipping OCSP revocation check")
		return nil
	}

	if len(cert.OCSPServer) == 0 {
		log.Printf("WARNING: certificate has no OCSP responder URLs, skipping revocation check")
		return nil
	}

	ocspURL := cert.OCSPServer[0]

	ocspReqBytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	httpResp, err := httpClient.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspReqBytes))
	if err != nil {
		return fmt.Errorf("OCSP request failed: %w", err)
	}
	defer func() {
		if err := httpResp.Body.Close(); err != nil {
			log.Printf("warning: failed to close OCSP response body: %v", err)
		}
	}()

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read OCSP response: %w", err)
	}

	ocspResponse, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	switch ocspResponse.Status {
	case ocsp.Good:
		return nil
	case ocsp.Revoked:
		return fmt.Errorf("certificate has been revoked (revoked at: %s)",
			ocspResponse.RevokedAt.Format(time.RFC3339))
	case ocsp.Unknown:
		log.Printf("WARNING: OCSP responder returned unknown status for certificate")
		return nil
	default:
		log.Printf("WARNING: OCSP responder returned unexpected status %d", ocspResponse.Status)
		return nil
	}
}
