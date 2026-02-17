package screens

import "github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"

type groupedIdentities struct {
	Personal       []pkcs12store.Identity
	Representation []pkcs12store.Identity
}
