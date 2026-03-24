package test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	// Generate Key/Cert with Spanish-style DN including serialNumber for identity cross-check
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "365", "-nodes",
		"-subj", "/CN=USER INTEGRATION TEST - 12345678Z/serialNumber=IDCES-12345678Z/GN=TEST/SN=USER INTEGRATION")
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
	defer func() {
		if err := p12File.Close(); err != nil {
			t.Logf("warning: failed to close p12 file: %v", err)
		}
	}()

	identity, err := store.Import(ctx, filepath.Base(p12Path), p12File, []byte("password"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Create a proposal via the API, then fetch its manifest.
	// Requires the webapp API to be running on localhost:8080 with MongoDB.
	portalURL := "http://localhost:8080"
	proposalBody := `{
		"targetSignatures": 10,
		"proposal": {
			"title": "Integration Test Proposal",
			"promoter": "Test Suite",
			"jurisdiction": "Catalunya",
			"summary": "Automated integration test",
			"legalStatement": "By signing this, I support this test",
			"fullTextURL": "https://example.com/test.pdf",
			"fullTextSHA256": "dGVzdGhhc2gxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ="
		}
	}`
	createReq, err := http.NewRequest("POST", portalURL+"/api/proposals", strings.NewReader(proposalBody))
	if err != nil {
		t.Fatalf("Failed to create proposal request: %v", err)
	}
	createReq.Header.Set("Content-Type", "application/json")
	if apiKey := os.Getenv("ORGANIZER_API_KEY"); apiKey != "" {
		createReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Skipf("Skipping: webapp API not reachable: %v", err)
	}
	defer func() { _ = createResp.Body.Close() }()
	if createResp.StatusCode != http.StatusCreated {
		t.Skipf("Skipping: proposal creation failed with status %d", createResp.StatusCode)
	}

	var created struct {
		RequestID string `json:"requestId"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("Failed to decode create response: %v", err)
	}

	reqURL := portalURL + "/request/" + created.RequestID
	req, _, err := net.Fetch(ctx, reqURL)
	if err != nil {
		t.Fatalf("Fetch manifest: %v", err)
	}

	// Sign (same flow as the desktop client)
	signer, err := store.Unlock(ctx, identity.ID)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Generate ILP XML (the content that gets signed)
	signerData := model.Signant{
		Nom:             "TEST",
		Cognom1:         "USER",
		Cognom2:         "INTEGRATION",
		TipusIdentifica: "DNI",
		NumIdentifica:   "12345678Z",
		DataNaixement:   "1990-01-01",
	}
	xmlBytes, err := model.GenerateILPXML(req, signerData)
	if err != nil {
		t.Fatalf("GenerateILPXML: %v", err)
	}

	// CAdES detached signature over the XML
	sig, err := cades.SignDetached(ctx, signer, identity.Cert, identity.Chain, xmlBytes, cades.SignOpts{
		SigningTime: time.Now(),
		Policy:      req.Policy,
	})
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}

	// Submit
	payloadHash := sha256.Sum256(xmlBytes)
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
		SignerXMLBase64:        base64.StdEncoding.EncodeToString(xmlBytes),
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

	if receipt.Status != "accepted" {
		t.Errorf("Receipt status: got %q, want %q", receipt.Status, "accepted")
	}
	t.Logf("Signature accepted, requestId=%s", req.RequestID)
}
