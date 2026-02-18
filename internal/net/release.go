package net

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	latestReleaseAPIURL  = "https://api.github.com/repos/vocdoni/vocsign/releases/latest"
	LatestReleasePageURL = "https://github.com/vocdoni/vocsign/releases/latest"
)

type latestReleaseResponse struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

func FetchLatestRelease(ctx context.Context) (string, string, error) {
	log.Printf("DEBUG: FetchLatestRelease request url=%s", latestReleaseAPIURL)
	req, err := http.NewRequestWithContext(ctx, "GET", latestReleaseAPIURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("build latest release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vocsign-version-check")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()
	log.Printf("DEBUG: FetchLatestRelease response status=%s", resp.Status)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return "", "", fmt.Errorf("latest release request failed: %s", msg)
	}

	var out latestReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("decode latest release response: %w", err)
	}
	if out.TagName == "" {
		return "", "", fmt.Errorf("latest release response missing tag_name")
	}
	if out.HTMLURL == "" {
		out.HTMLURL = LatestReleasePageURL
	}
	log.Printf("DEBUG: FetchLatestRelease parsed tag=%s url=%s", out.TagName, out.HTMLURL)
	return out.TagName, out.HTMLURL, nil
}
