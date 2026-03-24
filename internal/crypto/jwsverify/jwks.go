package jwsverify

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// Response body size limits.
const (
	maxResponseBytes int64 = 10 << 20 // 10 MB for sign requests and receipts
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
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: jwksCheckRedirect,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS body: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, fmt.Errorf("JWKS response exceeds %d bytes", maxResponseBytes)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}
	return &jwks, nil
}

// jwksCheckRedirect rejects redirects that downgrade from HTTPS to HTTP
// (unless the target is localhost/127.0.0.1).
func jwksCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	u := req.URL
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return fmt.Errorf("redirect to disallowed URL: %s", u.Redacted())
	}
	return nil
}

func (jwk *JWK) ToPublicKey() (crypto.PublicKey, error) {
	if jwk.KTY != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
	if jwk.CRV != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", jwk.CRV)
	}
	if jwk.ALG != "" && jwk.ALG != "ES256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", jwk.ALG)
	}
	if jwk.USE != "" && jwk.USE != "sig" {
		return nil, fmt.Errorf("key use %q is not valid for signature verification", jwk.USE)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate: %w", err)
	}

	// Use crypto/ecdh for on-curve validation (replaces deprecated elliptic.IsOnCurve).
	// Uncompressed point format: 0x04 || X || Y
	uncompressed := make([]byte, 1+len(xBytes)+len(yBytes))
	uncompressed[0] = 0x04
	copy(uncompressed[1:], xBytes)
	copy(uncompressed[1+len(xBytes):], yBytes)

	// Validate the point is on the curve using the non-deprecated crypto/ecdh API.
	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("invalid EC point: %w", err)
	}

	// Construct ecdsa.PublicKey for signature verification.
	// The point is validated above; construct directly from the coordinates.
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
