//go:build darwin && cgo

package systemstore

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/github/smimesign/certstore"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
)

type OSStore struct {
	Label string
}

func (s *OSStore) List(ctx context.Context) ([]pkcs12store.Identity, error) {
	st, err := certstore.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open system store: %w", err)
	}
	defer st.Close()

	identities, err := st.Identities()
	if err != nil {
		return nil, fmt.Errorf("failed to list system identities: %w", err)
	}

	var result []pkcs12store.Identity
	for _, id := range identities {
		cert, err := id.Certificate()
		if err != nil {
			continue
		}

		if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			continue
		}

		if cert.KeyUsage != 0 && (cert.KeyUsage&x509.KeyUsageDigitalSignature == 0) && (cert.KeyUsage&x509.KeyUsageContentCommitment == 0) {
			continue
		}

		signer, err := id.Signer()
		if err != nil || signer == nil {
			continue
		}

		displayName := cert.Subject.CommonName
		if displayName == "" {
			displayName = cert.Subject.String()
		}

		chain, _ := id.CertificateChain()

		result = append(result, pkcs12store.Identity{
			ID:             fmt.Sprintf("os:%x", pkcs12store.Fingerprint(cert)),
			FriendlyName:   fmt.Sprintf("[%s] %s", s.Label, displayName),
			Cert:           cert,
			Chain:          chain,
			Fingerprint256: pkcs12store.Fingerprint(cert),
			Signer:         signer,
		})
	}

	return result, nil
}
