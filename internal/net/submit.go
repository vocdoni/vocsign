package net

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vocdoni/gofirma/vocsign/internal/model"
)

func Submit(ctx context.Context, callbackURL string, resp *model.SignResponse) (*model.SubmitReceipt, error) {
	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", callbackURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submit failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK && httpResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		if len(body) > 0 {
			return nil, fmt.Errorf("unexpected status code: %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
		}
		return nil, fmt.Errorf("unexpected status code: %d", httpResp.StatusCode)
	}

	var receipt model.SubmitReceipt
	if err := json.NewDecoder(httpResp.Body).Decode(&receipt); err != nil {
		return nil, fmt.Errorf("failed to decode receipt: %w", err)
	}

	return &receipt, nil
}
