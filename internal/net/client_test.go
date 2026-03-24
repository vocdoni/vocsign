package net

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIsAllowedURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		allowed bool
	}{
		{"HTTPS is allowed", "https://example.com/path", true},
		{"HTTP localhost is allowed", "http://localhost:8080/path", true},
		{"HTTP 127.0.0.1 is allowed", "http://127.0.0.1:9090/path", true},
		{"HTTP other host is rejected", "http://example.com/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("Failed to parse URL %q: %v", tt.rawURL, err)
			}
			got := isAllowedURL(u)
			if got != tt.allowed {
				t.Errorf("isAllowedURL(%q) = %v, want %v", tt.rawURL, got, tt.allowed)
			}
		})
	}

	t.Run("Empty scheme is rejected", func(t *testing.T) {
		u := &url.URL{Scheme: "", Host: "example.com", Path: "/path"}
		if isAllowedURL(u) {
			t.Error("isAllowedURL with empty scheme should return false")
		}
	})
}

func TestCheckRedirect(t *testing.T) {
	makeReq := func(rawURL string) *http.Request {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("Failed to parse URL %q: %v", rawURL, err)
		}
		return &http.Request{URL: u}
	}

	t.Run("HTTPS redirect is allowed", func(t *testing.T) {
		req := makeReq("https://example.com/new")
		via := []*http.Request{makeReq("https://example.com/old")}
		if err := checkRedirect(req, via); err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})

	t.Run("localhost HTTP redirect is allowed", func(t *testing.T) {
		req := makeReq("http://localhost:8080/new")
		via := []*http.Request{makeReq("https://example.com/old")}
		if err := checkRedirect(req, via); err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})

	t.Run("HTTP to external host is rejected", func(t *testing.T) {
		req := makeReq("http://evil.com/steal")
		via := []*http.Request{makeReq("https://example.com/old")}
		err := checkRedirect(req, via)
		if err == nil {
			t.Error("Expected error for HTTP redirect to external host, got nil")
		}
	})

	t.Run("rejected after 10 redirects", func(t *testing.T) {
		req := makeReq("https://example.com/final")
		via := make([]*http.Request, 10)
		for i := range via {
			via[i] = makeReq("https://example.com/hop")
		}
		err := checkRedirect(req, via)
		if err == nil {
			t.Error("Expected error after 10 redirects, got nil")
		}
		if !strings.Contains(err.Error(), "10 redirects") {
			t.Errorf("Expected error about 10 redirects, got: %v", err)
		}
	})
}

func TestReadAll(t *testing.T) {
	t.Run("within limit succeeds", func(t *testing.T) {
		data := "hello world"
		got, err := readAll(strings.NewReader(data), 1024)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if string(got) != data {
			t.Errorf("Expected %q, got %q", data, string(got))
		}
	})

	t.Run("over limit returns error", func(t *testing.T) {
		data := "this is way too long"
		_, err := readAll(strings.NewReader(data), 5)
		if err == nil {
			t.Fatal("Expected error for body exceeding limit, got nil")
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("Expected error about exceeding limit, got: %v", err)
		}
	})

	t.Run("empty body returns empty bytes", func(t *testing.T) {
		got, err := readAll(bytes.NewReader(nil), 1024)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("Expected empty bytes, got %q", string(got))
		}
	})
}

func TestNewClient(t *testing.T) {
	timeout := 5 * time.Second
	client := newClient(timeout)

	if client == nil {
		t.Fatal("newClient returned nil")
	}
	if client.Timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, client.Timeout)
	}
}
