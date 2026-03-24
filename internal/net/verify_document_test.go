package net

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyDocumentHash_Match(t *testing.T) {
	content := []byte("This is the full text of the legislative proposal.")
	hash := sha256.Sum256(content)
	expectedHash := base64.StdEncoding.EncodeToString(hash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	err := VerifyDocumentHash(context.Background(), srv.URL, expectedHash)
	if err != nil {
		t.Fatalf("Expected no error for matching hash, got: %v", err)
	}
}

func TestVerifyDocumentHash_Mismatch(t *testing.T) {
	content := []byte("This is the real document content.")
	wrongHash := base64.StdEncoding.EncodeToString([]byte("not-a-real-sha256-hash-value-1234"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	err := VerifyDocumentHash(context.Background(), srv.URL, wrongHash)
	if err == nil {
		t.Fatal("Expected error for mismatched hash, got nil")
	}
	if !strings.Contains(err.Error(), "document hash mismatch") {
		t.Errorf("Expected error about hash mismatch, got: %v", err)
	}
}

func TestVerifyDocumentHash_Unreachable(t *testing.T) {
	// Use a URL that will not be reachable (port 0 on localhost)
	err := VerifyDocumentHash(context.Background(), "http://127.0.0.1:0/nonexistent", "dGVzdA==")
	if err == nil {
		t.Fatal("Expected error for unreachable URL, got nil")
	}
	if !strings.Contains(err.Error(), "failed to download document") {
		t.Errorf("Expected error about download failure, got: %v", err)
	}
}
