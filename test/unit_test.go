package test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
	"time"
	"net/url"
	"path/filepath"

	"github.com/vocdoni/gofirma/vocsign/internal/canon"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/cades"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
)

func TestEndToEndWithGeneratedCert(t *testing.T) {
	// Setup
	certsDir := "certs"
	p12Path := filepath.Join(certsDir, "user.p12")
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		t.Fatalf("Certificate not found. Run gen_certs.sh first.")
	}

	// Setup Store
	tmpDir := t.TempDir()
	storeDir := filepath.Join(tmpDir, "store")
	store, err := pkcs12store.NewFileStore(storeDir, []byte("vaultpw"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	// Import Identity
	ctx := context.Background()
	p12File, err := os.Open(p12Path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer p12File.Close()

	identity, err := store.Import(ctx, "Test User", p12File, []byte("password"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Verify Identity
	if identity.FriendlyName != "Test User" {
		t.Errorf("FriendlyName mismatch: %s", identity.FriendlyName)
	}
	
	// Try Fetch (Optional, if devcollector running)
	// We mock the request instead to be self-contained
	req := &model.SignRequest{
		Version:   "1.0",
		RequestID: "test-req-123",
		Nonce:     "dGVzdG5vbmce",
		IssuedAt:  time.Now().Format(time.RFC3339),
		ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
		Proposal: model.Proposal{
			Title:        "Test Proposal",
			Promoter:     "Test Promoter",
			Jurisdiction: "Test Jurisdiction",
			Summary:      "Test Summary",
			FullText: model.FullText{
				URL:    "https://example.com/doc",
				SHA256: "Gvj/Kk/Jc+j8+j8+j8+j8+j8+j8+j8+j8+j8+j8+j88=",
			},
		},
		Callback: model.Callback{
			URL:    "https://example.com/callback",
			Method: "POST",
		},
		Policy: &model.SignPolicy{
			Mode: "none",
		},
	}

	// Sign
	signer, err := store.Unlock(ctx, identity.ID)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	u, _ := url.Parse(req.Callback.URL)
	callbackHost := u.Host
	
	payload := model.SignPayload{
		Version:      "1.0",
		RequestID:    req.RequestID,
		Nonce:        req.Nonce,
		IssuedAt:     req.IssuedAt,
		ExpiresAt:    req.ExpiresAt,
		Proposal: model.PayloadProposal{
			Title:          req.Proposal.Title,
			Promoter:       req.Proposal.Promoter,
			Jurisdiction:   req.Proposal.Jurisdiction,
			FullTextSHA256: req.Proposal.FullText.SHA256,
		},
		CallbackHost: callbackHost,
		Policy:       req.Policy,
	}

	payloadBytes, err := canon.Encode(payload)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	sig, err := cades.SignDetached(ctx, signer, identity.Cert, identity.Chain, payloadBytes, cades.SignOpts{
		SigningTime: time.Now(),
		Policy:      req.Policy,
	})
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}

	t.Logf("Signature size: %d bytes", len(sig))
	
	// Optional: Submit (Mocked)
	payloadHash := sha256.Sum256(payloadBytes)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Cert.Raw}))
	
	resp := &model.SignResponse{
		Version:                "1.0",
		RequestID:              req.RequestID,
		Nonce:                  req.Nonce,
		SignedAt:               time.Now().Format(time.RFC3339),
		PayloadCanonicalSHA256: base64.StdEncoding.EncodeToString(payloadHash[:]),
		SignatureFormat:        "CAdES-detached",
		SignatureDerBase64:     base64.StdEncoding.EncodeToString(sig),
		SignerCertPEM:          certPEM,
		Client: model.ClientInfo{
			App:     "vocsign-test",
			Version: "0.0.1",
			OS:      "linux",
		},
	}
	
	// Just print response
	_ = resp
}
