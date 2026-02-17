//go:build !cgo || !darwin

package systemstore

import (
	"context"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
)

type OSStore struct {
	Label string
}

func (s *OSStore) List(ctx context.Context) ([]pkcs12store.Identity, error) {
	// Native OS store is currently only implemented on macOS in this project.
	return nil, nil
}
