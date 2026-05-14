package net

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Response body size limits.
const (
	maxResponseBytes int64 = 10 << 20 // 10 MB for sign requests and receipts
)

// newClient returns an http.Client that rejects redirects which downgrade from
// HTTPS to HTTP (unless the target is localhost/127.0.0.1). This prevents a
// malicious server from redirecting a validated HTTPS URL to an internal HTTP
// endpoint, bypassing the scheme check in model.Validate().
func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
	}
}

// checkRedirect ensures every redirect target uses HTTPS or targets localhost.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	if !isAllowedURL(req.URL) {
		return fmt.Errorf("redirect to disallowed URL: %s", req.URL.Redacted())
	}
	return nil
}

// isAllowedURL checks that a URL uses HTTPS, or targets localhost/127.0.0.1.
func isAllowedURL(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1"
}

// readAll reads up to limit bytes from r. Returns an error if the body
// exceeds the limit.
func readAll(r io.Reader, limit int64) ([]byte, error) {
	lr := io.LimitReader(r, limit+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeds %d bytes", limit)
	}
	return data, nil
}
