package test

import (
	"context"
	"os"
	"testing"
	"time"
	"path/filepath"

	"github.com/vocdoni/gofirma/vocsign/internal/crypto/cades"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
	"github.com/smallstep/pkcs7"
)

func TestLegalComplianceXML(t *testing.T) {
	// Setup Identity
	certsDir := "certs"
	p12Path := filepath.Join(certsDir, "user.p12")
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		t.Skip("Certificate not found. Run gen_certs.sh first.")
	}

	tmpDir := t.TempDir()
	store, _ := pkcs12store.NewFileStore(filepath.Join(tmpDir, "store"), []byte("vaultpw"))
	p12File, _ := os.Open(p12Path)
	identity, _ := store.Import(context.Background(), "Test", p12File, []byte("password"))
	signer, _ := store.Unlock(context.Background(), identity.ID)

	// Mock Request
	req := &model.SignRequest{
		Version:   "1.0",
		RequestID: "ILP-2026-001",
		Proposal: model.Proposal{
			Title: "LLEI DE MESURES PER L'HABITATGE",
		},
	}

	// Signer Data
	signerData := model.Signant{
		Nom:             "PAU",
		Cognom1:         "ESCRICH",
		Cognom2:         "GARCIA",
		TipusIdentifica: "DNI",
		NumIdentifica:   "47824166J",
		DataNaixement:   "1988-05-15",
	}

	// 1. Generate XML
	xmlBytes, err := model.GenerateILPXML(req, signerData)
	if err != nil {
		t.Fatalf("GenerateILPXML failed: %v", err)
	}
	t.Logf("Generated XML:\n%s", string(xmlBytes))

	// 2. Sign XML (CAdES detached)
	sig, err := cades.SignDetached(context.Background(), signer, identity.Cert, identity.Chain, xmlBytes, cades.SignOpts{
		SigningTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("SignDetached failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("Generated signature is empty")
	}
	t.Logf("Signature size: %d bytes", len(sig))

	// 3. Verify Signature (Server-side logic)
	p7, err := pkcs7.Parse(sig)
	if err != nil {
		t.Fatalf("Parse CMS failed: %v", err)
	}
	p7.Content = xmlBytes
	if err := p7.Verify(); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	} else {
		t.Log("Signature verified successfully in test")
	}
}
