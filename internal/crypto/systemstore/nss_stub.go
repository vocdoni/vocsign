//go:build !cgo

package systemstore

import (
	"context"

	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
)

// NSSStore is unavailable when cgo is disabled.
type NSSStore struct {
	LibPath    string
	ProfileDir string
	Label      string
}

func DiscoverNSSStores(ctx context.Context) []*NSSStore {
	return nil
}

func (s *NSSStore) List(ctx context.Context) ([]pkcs12store.Identity, error) {
	return nil, nil
}
