package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/systemstore"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
	"github.com/vocdoni/gofirma/vocsign/internal/storage"
	"gioui.org/x/explorer"
)

type Screen int

const (
	ScreenOpenRequest Screen = iota
	ScreenCertificates
	ScreenAudit
	ScreenRequestDetails
	ScreenWizard
)

type App struct {
	mu           sync.Mutex
	CurrentScreen Screen
	ShowWizard    bool
	
	// Services
	Store       pkcs12store.Store
	AuditLogger *storage.AuditLogger
	Explorer    *explorer.Explorer

	// State
	Identities       []pkcs12store.Identity
	SystemIdentities []pkcs12store.Identity
	
	// Current Action State
	CurrentReq  *model.SignRequest
	RawReq      []byte
	ReqError    error
	FetchStatus string
	SignStatus  string
	SignResponse *model.SignResponse
	
	// UI Actions
	RequestURL string
	Invalidate func()
}

func (a *App) ScanSystemStores(ctx context.Context) {
	var all []pkcs12store.Identity

	// 1. OS-Native Store
	osStore := &systemstore.OSStore{Label: "System"}
	ids, err := osStore.List(ctx)
	if err == nil {
		all = append(all, ids...)
	}

	// 2. NSS Stores
	nssStores := systemstore.DiscoverNSSStores()
	for _, s := range nssStores {
		ids, err := s.List(ctx)
		if err == nil {
			all = append(all, ids...)
		}
	}
	
	a.mu.Lock()
	defer a.mu.Unlock()
	
	// Deduplicate based on Fingerprint
	seen := make(map[string]bool)
	for _, id := range a.Identities {
		seen[fmt.Sprintf("%x", id.Fingerprint256)] = true
	}
	
	var filtered []pkcs12store.Identity
	for _, sid := range all {
		fp := fmt.Sprintf("%x", sid.Fingerprint256)
		if !seen[fp] {
			filtered = append(filtered, sid)
			seen[fp] = true 
		}
	}
	
	a.SystemIdentities = filtered
}

func NewApp() (*App, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home dir: %w", err)
	}
	appDataDir := filepath.Join(home, ".vocsign")
	if err := os.MkdirAll(appDataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create app data dir: %w", err)
	}

	logger, err := storage.NewAuditLogger(appDataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	storeDir := filepath.Join(appDataDir, "store")
	vaultPW := []byte("default-vault-password")
	store, err := pkcs12store.NewFileStore(storeDir, vaultPW)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	app := &App{
		CurrentScreen: ScreenOpenRequest,
		AuditLogger:   logger,
		Store:         store,
	}

	// Initial load
	ids, _ := store.List(context.Background())
	app.Identities = ids

	if len(ids) == 0 {
		app.ShowWizard = true
		app.CurrentScreen = ScreenWizard
	}

	return app, nil
}
