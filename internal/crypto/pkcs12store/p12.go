package pkcs12store

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"

	"software.sslmate.com/src/go-pkcs12"
)

// Fingerprint returns the SHA-256 fingerprint for a certificate.
func Fingerprint(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// ParsePKCS12 parses a PKCS#12/PFX identity and returns signer and certificate chain.
// It supports both password-protected and password-less files. For legacy BER-encoded files,
// it retries using BER-to-DER normalization.
func ParsePKCS12(r io.Reader, password string) (crypto.Signer, *x509.Certificate, []*x509.Certificate, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, nil, err
	}

	attempts := newDefaultAttemptSource().Build(data, password)
	priv, cert, chain, err := decodeWithAttempts(pkcs12.DecodeChain, attempts, password)
	if err != nil {
		return nil, nil, nil, err
	}
	return verifySigner(priv, cert, chain)
}

func verifySigner(priv interface{}, cert *x509.Certificate, chain []*x509.Certificate) (crypto.Signer, *x509.Certificate, []*x509.Certificate, error) {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.New("parsed private key does not support signing")
	}
	return signer, cert, chain, nil
}

func alternatePasswords(password string) []string {
	var out []string
	add := func(candidate string) {
		if candidate == password {
			return
		}
		for _, existing := range out {
			if existing == candidate {
				return
			}
		}
		out = append(out, candidate)
	}

	// Keep empty-password fallback for interoperating with passwordless exports.
	add("")
	return out
}
