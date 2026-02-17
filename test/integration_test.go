package test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"testing"
	"time"
	"net/url"
	"path/filepath"

	"github.com/vocdoni/gofirma/vocsign/internal/canon"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/cades"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
	"github.com/vocdoni/gofirma/vocsign/internal/net"
)

func TestEndToEnd(t *testing.T) {
	// Generate Key/Cert/P12 using OpenSSL
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	certPath := filepath.Join(tmpDir, "cert.pem")
	p12Path := filepath.Join(tmpDir, "identity.p12")

	// Generate Key/Cert
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "365", "-nodes", "-subj", "/CN=Test User")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}

	// Generate P12 (Legacy for compatibility)
	// We try with -legacy flag first, if fails (old openssl), try without
	cmd = exec.Command("openssl", "pkcs12", "-export", "-out", p12Path, "-inkey", keyPath, "-in", certPath, "-passout", "pass:password", "-legacy")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Try without -legacy
		cmd = exec.Command("openssl", "pkcs12", "-export", "-out", p12Path, "-inkey", keyPath, "-in", certPath, "-passout", "pass:password")
		if out2, err2 := cmd.CombinedOutput(); err2 != nil {
			t.Fatalf("openssl pkcs12: %v\n%s\nRetry: %v\n%s", err, out, err2, out2)
		}
	}

	// Setup Store
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

	identity, err := store.Import(ctx, filepath.Base(p12Path), p12File, []byte("password"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Fetch Request (Assumes devcollector is running on localhost:8080)
	reqURL := "http://localhost:8080/request"
	req, _, err := net.Fetch(ctx, reqURL)
	if err != nil {
		t.Skipf("Skipping test, devcollector not reachable: %v", err)
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

	// Submit
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

	receipt, err := net.Submit(ctx, req.Callback.URL, resp)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if receipt.Status != "ok" {
		t.Errorf("Receipt status: %s", receipt.Status)
	}
}
