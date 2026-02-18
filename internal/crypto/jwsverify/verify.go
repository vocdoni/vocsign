package jwsverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/vocdoni/gofirma/vocsign/internal/canon"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
)

func Verify(req *model.SignRequest) error {
	if req == nil {
		return fmt.Errorf("nil request")
	}
	if req.OrganizerSignature == nil {
		return fmt.Errorf("missing organizerSignature")
	}
	if req.OrganizerSignature.Value == "" {
		return fmt.Errorf("missing organizerSignature value")
	}
	if req.Organizer.JWKSetURL == "" {
		return fmt.Errorf("missing organizer jwkSetUrl")
	}
	if req.Organizer.KID == "" {
		return fmt.Errorf("missing organizer kid")
	}

	log.Printf("DEBUG: Verifying organizer signature for Request %s", req.RequestID)
	log.Printf("DEBUG: Fetching JWKS from %s", req.Organizer.JWKSetURL)
	jwks, err := FetchJWKS(req.Organizer.JWKSetURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	var pubKey *ecdsa.PublicKey
	for _, key := range jwks.Keys {
		if key.KID == req.Organizer.KID {
			log.Printf("DEBUG: Found matching key in JWKS (KID: %s)", key.KID)
			parsedKey, err := key.ToPublicKey()
			if err != nil {
				return fmt.Errorf("invalid key: %w", err)
			}
			ecKey, ok := parsedKey.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("unsupported key type for organizer signature")
			}
			pubKey = ecKey
			break
		}
	}
	if pubKey == nil {
		log.Printf("DEBUG: Key KID %s not found in JWKS", req.Organizer.KID)
		return fmt.Errorf("key not found: %s", req.Organizer.KID)
	}

	reqCopy := *req
	reqCopy.OrganizerSignature = nil

	canonicalBytes, err := canon.Encode(reqCopy)
	if err != nil {
		return fmt.Errorf("canonicalization failed: %w", err)
	}
	log.Printf("DEBUG: Canonical Request Body (len: %d)", len(canonicalBytes))

	parts := strings.Split(req.OrganizerSignature.Value, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWS format")
	}

	headerB64 := parts[0]
	payloadB64 := parts[1]
	signatureB64 := parts[2]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return fmt.Errorf("invalid JWS header encoding: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("invalid JWS header json: %w", err)
	}
	log.Printf("DEBUG: JWS Header: %v", header)
	if alg, ok := header["alg"].(string); !ok || alg != "ES256" {
		return fmt.Errorf("unsupported algorithm: %v", header["alg"])
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return fmt.Errorf("invalid JWS payload encoding: %w", err)
	}
	if string(payloadBytes) != string(canonicalBytes) {
		log.Printf("DEBUG: Payload mismatch!")
		log.Printf("DEBUG: Expected: %s", string(canonicalBytes))
		log.Printf("DEBUG: Got:      %s", string(payloadBytes))
		return fmt.Errorf("JWS payload does not match request body")
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid JWS signature encoding: %w", err)
	}
	if len(signatureBytes) != 64 {
		return fmt.Errorf("invalid ES256 signature length: %d", len(signatureBytes))
	}

	signedContent := headerB64 + "." + payloadB64
	hashed := sha256.Sum256([]byte(signedContent))

	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:])
	if !ecdsa.Verify(pubKey, hashed[:], r, s) {
		log.Printf("DEBUG: JWS Signature Verification FAILED")
		return fmt.Errorf("signature verification failed")
	}

	log.Printf("DEBUG: JWS Signature Verified Successfully")
	return nil
}
