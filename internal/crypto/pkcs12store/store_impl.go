package pkcs12store

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
)

type FileStore struct {
	mu      sync.Mutex
	dir     string
	vaultPW []byte // Session vault password
}

type PKCS11Ref struct {
	LibPath    string `json:"libPath"`
	ProfileDir string `json:"profileDir"`
	Slot       uint   `json:"slot"`
	CKAIDHex   string `json:"ckaIdHex"`
}

type OSNativeRef struct {
	FingerprintHex string `json:"fingerprintHex"`
}

type IdentityMeta struct {
	ID             string       `json:"id"`
	FriendlyName   string       `json:"friendlyName"`
	CertPEM        string       `json:"certPem"`
	ChainPEM       []string     `json:"chainPem"`
	FingerprintHex string       `json:"fingerprintHex"`
	PKCS11         *PKCS11Ref   `json:"pkcs11,omitempty"`
	OSNative       *OSNativeRef `json:"osNative,omitempty"`
}

func NewFileStore(dir string, vaultPW []byte) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create store dir: %w", err)
	}
	return &FileStore{
		dir:     dir,
		vaultPW: vaultPW,
	}, nil
}

func (s *FileStore) List(ctx context.Context) ([]Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read store dir: %w", err)
	}

	var identities []Identity
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			metaPath := filepath.Join(s.dir, entry.Name())
			metaBytes, err := os.ReadFile(metaPath)
			if err != nil {
				continue
			}
			var meta IdentityMeta
			if err := json.Unmarshal(metaBytes, &meta); err != nil {
				continue
			}

			certBlock, _ := pem.Decode([]byte(meta.CertPEM))
			if certBlock == nil {
				continue
			}
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				continue
			}

			var chain []*x509.Certificate
			for _, pemStr := range meta.ChainPEM {
				block, _ := pem.Decode([]byte(pemStr))
				if block != nil {
					c, _ := x509.ParseCertificate(block.Bytes)
					if c != nil {
						chain = append(chain, c)
					}
				}
			}

			fp := Fingerprint(cert)

			id := Identity{
				ID:             meta.ID,
				FriendlyName:   meta.FriendlyName,
				Cert:           cert,
				Chain:          chain,
				Fingerprint256: fp,
			}

			identities = append(identities, id)
		}
	}
	return identities, nil
}

func (s *FileStore) Import(ctx context.Context, name string, r io.Reader, password []byte) (*Identity, error) {
	signer, cert, chain, err := ParsePKCS12(r, string(password))
	if err != nil {
		return nil, fmt.Errorf("import failed: %w", err)
	}

	fp := Fingerprint(cert)
	if s.Exists(fp) {
		return nil, fmt.Errorf("%w", ErrImportDuplicate)
	}

	id := uuid.New().String()
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	encryptedKey, err := EncryptData(privKeyBytes, s.vaultPW)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	keyPath := filepath.Join(s.dir, id+".key.enc")
	if err := os.WriteFile(keyPath, encryptedKey, 0600); err != nil {
		return nil, fmt.Errorf("failed to save encrypted key: %w", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	var chainPEM []string
	for _, c := range chain {
		chainPEM = append(chainPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
	}

	meta := IdentityMeta{
		ID:             id,
		FriendlyName:   name,
		CertPEM:        certPEM,
		ChainPEM:       chainPEM,
		FingerprintHex: fmt.Sprintf("%x", fp),
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		os.Remove(keyPath)
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metaPath := filepath.Join(s.dir, id+".json")
	if err := os.WriteFile(metaPath, metaBytes, 0600); err != nil {
		os.Remove(keyPath)
		return nil, fmt.Errorf("failed to save metadata: %w", err)
	}

	return &Identity{
		ID:             id,
		FriendlyName:   meta.FriendlyName,
		Cert:           cert,
		Chain:          chain,
		Fingerprint256: fp,
		Signer:         signer,
	}, nil
}

func (s *FileStore) ImportSystem(ctx context.Context, id Identity, libPath, profileDir string, slot uint, ckaID []byte) error {
	if s.Exists(id.Fingerprint256) {
		return fmt.Errorf("%w", ErrImportDuplicate)
	}

	metaID := uuid.New().String()
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.Cert.Raw}))
	var chainPEM []string
	for _, c := range id.Chain {
		chainPEM = append(chainPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
	}

	meta := IdentityMeta{
		ID:             metaID,
		FriendlyName:   id.FriendlyName,
		CertPEM:        certPEM,
		ChainPEM:       chainPEM,
		FingerprintHex: fmt.Sprintf("%x", id.Fingerprint256),
	}
	if libPath == "" {
		meta.OSNative = &OSNativeRef{
			FingerprintHex: fmt.Sprintf("%x", id.Fingerprint256),
		}
	} else {
		meta.PKCS11 = &PKCS11Ref{
			LibPath:    libPath,
			ProfileDir: profileDir,
			Slot:       slot,
			CKAIDHex:   hex.EncodeToString(ckaID),
		}
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(s.dir, metaID+".json"), metaBytes, 0600)
}

func (s *FileStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	metaPath := filepath.Join(s.dir, id+".json")
	keyPath := filepath.Join(s.dir, id+".key.enc")

	os.Remove(metaPath)
	os.Remove(keyPath)
	return nil
}

func (s *FileStore) Exists(fingerprint [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, _ := os.ReadDir(s.dir)
	fpHex := fmt.Sprintf("%x", fingerprint)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			metaPath := filepath.Join(s.dir, entry.Name())
			metaBytes, _ := os.ReadFile(metaPath)
			var meta IdentityMeta
			if err := json.Unmarshal(metaBytes, &meta); err == nil {
				if meta.FingerprintHex == fpHex {
					return true
				}
			}
		}
	}
	return false
}

func (s *FileStore) Unlock(ctx context.Context, id string) (crypto.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	metaPath := filepath.Join(s.dir, id+".json")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}
	var meta IdentityMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if meta.PKCS11 != nil {
		ckaID, err := hex.DecodeString(meta.PKCS11.CKAIDHex)
		if err != nil {
			return nil, fmt.Errorf("invalid CKA_ID hex: %w", err)
		}

		certBlock, _ := pem.Decode([]byte(meta.CertPEM))
		if certBlock == nil {
			return nil, fmt.Errorf("missing certificate in metadata")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		return &PKCS11Signer{
			LibPath:    meta.PKCS11.LibPath,
			ProfileDir: meta.PKCS11.ProfileDir,
			Slot:       meta.PKCS11.Slot,
			ID:         ckaID,
			PublicKey:  cert.PublicKey,
		}, nil
	}
	if meta.OSNative != nil {
		return unlockOSNative(meta)
	}

	keyPath := filepath.Join(s.dir, id+".key.enc")
	encryptedKey, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key: %w", err)
	}

	privKeyBytes, err := DecryptData(encryptedKey, s.vaultPW)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a signer")
	}
	return signer, nil
}
