//go:build !cgo || !darwin

package pkcs12store

import (
	"crypto"
	"fmt"
)

func unlockOSNative(meta IdentityMeta) (crypto.Signer, error) {
	return nil, fmt.Errorf("OS native signer unavailable in this build")
}
