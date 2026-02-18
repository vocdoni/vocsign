package pkcs12store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParsePKCS12IDCatNoPassword(t *testing.T) {
	testParsePKCS12(t, fixturePath("test/certs/idcat_like_nopass.p12"), "")
}

func TestParsePKCS12PasswordProtected(t *testing.T) {
	testParsePKCS12(t, fixturePath("test/certs/user.p12"), "password")
}

func TestParsePKCS12WrongPassword(t *testing.T) {
	data, err := os.ReadFile(fixturePath("test/certs/user.p12"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	if _, _, _, err := ParsePKCS12(bytes.NewReader(data), "wrong-password"); err == nil {
		t.Fatal("expected parse error for wrong password")
	} else if !errors.Is(err, ErrImportWrongPassword) {
		t.Fatalf("expected ErrImportWrongPassword, got: %v", err)
	}
}

func TestParsePKCS12PasswordRequired(t *testing.T) {
	data, err := os.ReadFile(fixturePath("test/certs/user.p12"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	if _, _, _, err := ParsePKCS12(bytes.NewReader(data), ""); err == nil {
		t.Fatal("expected parse error for missing password")
	} else if !errors.Is(err, ErrImportPasswordRequired) {
		t.Fatalf("expected ErrImportPasswordRequired, got: %v", err)
	}
}

func TestParsePKCS12InvalidFile(t *testing.T) {
	data := []byte("not-a-pkcs12")
	if _, _, _, err := ParsePKCS12(bytes.NewReader(data), ""); err == nil {
		t.Fatal("expected parse error for invalid file")
	} else if !errors.Is(err, ErrImportInvalidFile) && !errors.Is(err, ErrImportUnsupported) {
		t.Fatalf("expected invalid/unsupported import error, got: %v", err)
	}
}

func testParsePKCS12(t *testing.T, p12Path, password string) {
	t.Helper()

	data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	signer, cert, chain, err := ParsePKCS12(bytes.NewReader(data), password)
	if err != nil {
		t.Fatalf("ParsePKCS12 failed: %v", err)
	}
	if signer == nil {
		t.Fatal("no private key found")
	}
	if cert == nil {
		t.Fatal("no certificate found")
	}
	t.Logf("Subject: %s", cert.Subject)
	t.Logf("CA Chain length: %d", len(chain))
}

func fixturePath(rel string) string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to resolve test file path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	return filepath.Join(repoRoot, filepath.FromSlash(rel))
}
