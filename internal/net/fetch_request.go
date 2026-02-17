package net

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/vocdoni/gofirma/vocsign/internal/model"
)

// Fetch retrieves and parses a SignRequest from a URL.
func Fetch(ctx context.Context, url string) (*model.SignRequest, []byte, error) {
	log.Printf("DEBUG: Fetching request from %s", url)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("DEBUG: Fetch failed: %v", err)
		return nil, nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("DEBUG: HTTP Response Status: %s", resp.Status)
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}
	log.Printf("DEBUG: Received %d bytes", len(raw))

	var signReq model.SignRequest
	if err := json.Unmarshal(raw, &signReq); err != nil {
		log.Printf("DEBUG: JSON Unmarshal failed: %v", err)
		return nil, nil, fmt.Errorf("failed to unmarshal json: %w", err)
	}

	log.Printf("DEBUG: Parsed Request ID: %s", signReq.RequestID)
	return &signReq, raw, nil
}
