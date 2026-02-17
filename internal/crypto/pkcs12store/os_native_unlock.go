//go:build darwin && cgo

package pkcs12store

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/github/smimesign/certstore"
)

func unlockOSNative(meta IdentityMeta) (crypto.Signer, error) {
	target, err := hex.DecodeString(meta.OSNative.FingerprintHex)
	if err != nil || len(target) != sha256.Size {
		return nil, fmt.Errorf("invalid OS native fingerprint reference")
	}

	st, err := certstore.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open system store: %w", err)
	}
	defer st.Close()

	identities, err := st.Identities()
	if err != nil {
		return nil, fmt.Errorf("failed to list system identities: %w", err)
	}

	for _, id := range identities {
		cert, certErr := id.Certificate()
		if certErr != nil || cert == nil {
			continue
		}
		fp := sha256.Sum256(cert.Raw)
		if !bytes.Equal(fp[:], target) {
			continue
		}
		signer, signErr := id.Signer()
		if signErr != nil || signer == nil {
			if signErr == nil {
				signErr = fmt.Errorf("signer is nil")
			}
			return nil, fmt.Errorf("failed to access signer from system store: %w", signErr)
		}
		return signer, nil
	}

	return nil, fmt.Errorf("system certificate no longer available")
}
