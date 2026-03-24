package net

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// VerifyDocumentHash downloads the document at docURL, computes its SHA-256
// hash, and verifies it matches expectedHashBase64 (the base64-encoded hash
// from the sign request manifest). This prevents proposal creators from
// changing the document after people start signing.
func VerifyDocumentHash(ctx context.Context, docURL string, expectedHashBase64 string) error {
	if docURL == "" {
		return fmt.Errorf("document URL is empty")
	}
	if expectedHashBase64 == "" {
		return fmt.Errorf("expected document hash is empty")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", docURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for document: %w", err)
	}

	client := newClient(30 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("document download returned status %d", resp.StatusCode)
	}

	body, err := readAll(resp.Body, maxResponseBytes)
	if err != nil {
		return fmt.Errorf("failed to read document body: %w", err)
	}

	actualHash := sha256.Sum256(body)
	actualHashBase64 := base64.StdEncoding.EncodeToString(actualHash[:])

	if actualHashBase64 != expectedHashBase64 {
		return fmt.Errorf(
			"document hash mismatch: expected %s but got %s",
			expectedHashBase64, actualHashBase64,
		)
	}

	return nil
}
