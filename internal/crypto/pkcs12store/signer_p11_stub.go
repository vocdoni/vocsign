//go:build !cgo

package pkcs12store

import (
	"crypto"
	"errors"
	"io"
)

// PKCS11Signer is unavailable when cgo is disabled.
type PKCS11Signer struct {
	LibPath    string
	ProfileDir string
	Slot       uint
	ID         []byte
	PublicKey  crypto.PublicKey
}

func (s *PKCS11Signer) Public() crypto.PublicKey {
	return s.PublicKey
}

func (s *PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("pkcs11 signing is unavailable in this build (cgo disabled)")
}
