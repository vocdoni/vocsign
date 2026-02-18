package jwsverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	ALG string `json:"alg"`
	USE string `json:"use"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func FetchJWKS(url string) (*JWKS, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch failed with status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}
	return &jwks, nil
}

func (jwk *JWK) ToPublicKey() (crypto.PublicKey, error) {
	if jwk.KTY != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
	if jwk.CRV != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", jwk.CRV)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid EC point")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
