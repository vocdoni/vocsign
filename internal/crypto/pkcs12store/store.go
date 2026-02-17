package pkcs12store

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
)

type Identity struct {
	ID             string
	FriendlyName   string
	Cert           *x509.Certificate
	Chain          []*x509.Certificate
	Fingerprint256 [32]byte
	Signer         crypto.Signer
}

type Store interface {
	List(ctx context.Context) ([]Identity, error)
	Import(ctx context.Context, name string, r io.Reader, password []byte) (*Identity, error)
	ImportSystem(ctx context.Context, id Identity, libPath, profileDir string, slot uint, ckaID []byte) error
	Delete(ctx context.Context, id string) error
	Unlock(ctx context.Context, id string) (crypto.Signer, error)
	Exists(fingerprint [32]byte) bool
}

var ErrNotFound = errors.New("identity not found")
