package systemstore

import (
	"context"

	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
)

type Store interface {
	List(ctx context.Context) ([]pkcs12store.Identity, error)
}

type Identity = pkcs12store.Identity
