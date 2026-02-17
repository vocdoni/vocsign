package jwsverify

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/vocdoni/gofirma/vocsign/internal/canon"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
)

func Verify(req *model.SignRequest) error {
	log.Printf("DEBUG: Verifying organizer signature for Request %s", req.RequestID)
	// 1. Fetch JWKS
	log.Printf("DEBUG: Fetching JWKS from %s", req.Organizer.JWKSetURL)
	jwks, err := FetchJWKS(req.Organizer.JWKSetURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// 2. Find Key
	var pubKey *rsa.PublicKey
	for _, key := range jwks.Keys {
		if key.KID == req.Organizer.KID {
			log.Printf("DEBUG: Found matching key in JWKS (KID: %s)", key.KID)
			pubKey, err = key.ToPublicKey()
			if err != nil {
				return fmt.Errorf("invalid key: %w", err)
			}
			break
		}
	}
	if pubKey == nil {
		log.Printf("DEBUG: Key KID %s not found in JWKS", req.Organizer.KID)
		return fmt.Errorf("key not found: %s", req.Organizer.KID)
	}

	// 3. Canonicalize Request (excluding OrganizerSignature)
	reqCopy := *req
	reqCopy.OrganizerSignature = nil

	canonicalBytes, err := canon.Encode(reqCopy)
	if err != nil {
		return fmt.Errorf("canonicalization failed: %w", err)
	}
	log.Printf("DEBUG: Canonical Request Body (len: %d)", len(canonicalBytes))

	// 4. Verify JWS
	parts := strings.Split(req.OrganizerSignature.Value, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWS format")
	}

	headerB64 := parts[0]
	payloadB64 := parts[1]
	signatureB64 := parts[2]

	// Verify Header
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return fmt.Errorf("invalid JWS header encoding: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("invalid JWS header json: %w", err)
	}
	log.Printf("DEBUG: JWS Header: %v", header)
	if alg, ok := header["alg"].(string); !ok || alg != "RS256" {
		return fmt.Errorf("unsupported algorithm: %v", header["alg"])
	}

	// Verify Payload matches Canonical Request
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

	// Verify Signature
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid JWS signature encoding: %w", err)
	}

	signedContent := headerB64 + "." + payloadB64
	hashed := sha256.Sum256([]byte(signedContent))

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signatureBytes); err != nil {
		log.Printf("DEBUG: JWS Signature Verification FAILED")
		return fmt.Errorf("signature verification failed: %w", err)
	}

	log.Printf("DEBUG: JWS Signature Verified Successfully")
	return nil
}
