package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"gioui.org/x/explorer"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/systemstore"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
	appnet "github.com/vocdoni/gofirma/vocsign/internal/net"
	"github.com/vocdoni/gofirma/vocsign/internal/storage"
	"github.com/vocdoni/gofirma/vocsign/internal/version"
)

type Screen int

const (
	ScreenOpenRequest Screen = iota
	ScreenCertificates
	ScreenAudit
	ScreenAbout
	ScreenRequestDetails
	ScreenWizard
)

type App struct {
	mu            sync.RWMutex
	CurrentScreen Screen
	ShowWizard    bool
	BuildInfo     BuildInfo

	// Services
	Store       pkcs12store.Store
	AuditLogger *storage.AuditLogger
	Explorer    *explorer.Explorer

	// State
	Identities       []pkcs12store.Identity
	SystemIdentities []pkcs12store.Identity
	LockedP12        []string

	// Current Action State
	CurrentReq   *model.SignRequest
	RawReq       []byte
	ReqError     error
	FetchStatus  string
	SignStatus   string
	SignResponse *model.SignResponse

	// UI Actions
	RequestURL string
	Invalidate func()

	LatestVersion   string
	ReleasePageURL  string
	UpdateAvailable bool
	UpdateChecked   bool
	UpdateCheckErr  string
	UpdateMessage   string

	updateChecking bool
}

type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

type UpdateStatus struct {
	CurrentVersion string
	LatestVersion  string
	ReleasePageURL string
	Available      bool
	Checked        bool
	Checking       bool
	Error          string
	Message        string
}

func (a *App) SystemIdentitiesSnapshot() []pkcs12store.Identity {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]pkcs12store.Identity, len(a.SystemIdentities))
	copy(out, a.SystemIdentities)
	return out
}

func (a *App) IdentitiesSnapshot() []pkcs12store.Identity {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]pkcs12store.Identity, len(a.Identities))
	copy(out, a.Identities)
	return out
}

func (a *App) LockedP12Snapshot() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, len(a.LockedP12))
	copy(out, a.LockedP12)
	return out
}

func (a *App) SetIdentities(ids []pkcs12store.Identity) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]pkcs12store.Identity, len(ids))
	copy(out, ids)
	a.Identities = out
}

func (a *App) UpdateStatusSnapshot() UpdateStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return UpdateStatus{
		CurrentVersion: a.BuildInfo.Version,
		LatestVersion:  a.LatestVersion,
		ReleasePageURL: a.ReleasePageURL,
		Available:      a.UpdateAvailable,
		Checked:        a.UpdateChecked,
		Checking:       a.updateChecking,
		Error:          a.UpdateCheckErr,
		Message:        a.UpdateMessage,
	}
}

func (a *App) StartUpdateCheck() {
	a.runUpdateCheck(false)
}

func (a *App) CheckUpdatesNow() {
	a.runUpdateCheck(true)
}

func (a *App) runUpdateCheck(force bool) {
	a.mu.Lock()
	if a.updateChecking {
		a.mu.Unlock()
		return
	}
	if !force && a.UpdateChecked {
		log.Printf("DEBUG: update check skipped (already checked)")
		a.mu.Unlock()
		return
	}
	a.updateChecking = true
	a.UpdateMessage = "Checking for updates..."
	a.mu.Unlock()
	log.Printf("DEBUG: update check started (current=%s force=%v)", a.BuildInfo.Version, force)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		latest, releaseURL, err := appnet.FetchLatestRelease(ctx)

		a.mu.Lock()
		a.updateChecking = false
		a.UpdateChecked = true
		if err != nil {
			log.Printf("DEBUG: update check failed: %v", err)
			a.UpdateCheckErr = err.Error()
			a.UpdateMessage = "Update check failed"
			a.mu.Unlock()
			if a.Invalidate != nil {
				a.Invalidate()
			}
			return
		}
		a.UpdateCheckErr = ""
		a.LatestVersion = latest
		if releaseURL != "" {
			a.ReleasePageURL = releaseURL
		}
		a.UpdateAvailable = version.IsOutdated(a.BuildInfo.Version, latest)
		if a.UpdateAvailable {
			a.UpdateMessage = "New version available: " + latest
			log.Printf("DEBUG: update check result: outdated current=%s latest=%s", a.BuildInfo.Version, latest)
		} else {
			a.UpdateMessage = "You are using the latest version"
			log.Printf("DEBUG: update check result: up-to-date current=%s latest=%s", a.BuildInfo.Version, latest)
		}
		a.mu.Unlock()

		if a.Invalidate != nil {
			a.Invalidate()
		}
	}()
}

func (a *App) ScanSystemStores(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	start := time.Now()
	log.Printf("DEBUG: ScanSystemStores started")
	var all []pkcs12store.Identity

	// 1. OS-Native Store
	osStore := &systemstore.OSStore{Label: "System"}
	log.Printf("DEBUG: ScanSystemStores: scanning OS store %q", osStore.Label)
	ids, err := safeList(osStore.List, ctx, "OS store")
	if err == nil {
		all = append(all, ids...)
		log.Printf("DEBUG: ScanSystemStores: OS store returned %d identities", len(ids))
	} else {
		log.Printf("DEBUG: ScanSystemStores: OS store error: %v", err)
	}

	// 2. NSS Stores
	nssStores := systemstore.DiscoverNSSStores(ctx)
	log.Printf("DEBUG: ScanSystemStores: discovered %d NSS stores", len(nssStores))
	var nssMu sync.Mutex
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, s := range nssStores {
		s := s
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			log.Printf("DEBUG: ScanSystemStores: scanning NSS store label=%q profile=%q", s.Label, s.ProfileDir)
			ids, err := safeList(s.List, ctx, "NSS store "+s.Label)
			if err == nil {
				nssMu.Lock()
				all = append(all, ids...)
				nssMu.Unlock()
				log.Printf("DEBUG: ScanSystemStores: NSS store %q returned %d identities", s.Label, len(ids))
			} else {
				log.Printf("DEBUG: ScanSystemStores: NSS store %q error: %v", s.Label, err)
			}
		}()
	}
	wg.Wait()

	// 3. PKCS#12 files (passwordless only)
	var lockedP12 []string
	p12Paths := systemstore.FindPKCS12Candidates(ctx, 5, 200)
	log.Printf("DEBUG: ScanSystemStores: discovered %d candidate PKCS#12 files", len(p12Paths))
	for _, p := range p12Paths {
		id, err := systemstore.ParsePKCS12Metadata(p, "")
		if err != nil {
			if errors.Is(err, systemstore.ErrPKCS12PasswordRequired) {
				log.Printf("DEBUG: PKCS#12 file requires password, skipping auto-import: %s", p)
				lockedP12 = append(lockedP12, p)
			} else {
				log.Printf("DEBUG: PKCS#12 parse skipped for %s: %v", p, err)
			}
			continue
		}
		all = append(all, id)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.LockedP12 = lockedP12

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
	log.Printf("DEBUG: ScanSystemStores finished in %s, total=%d, new=%d", time.Since(start), len(all), len(filtered))
}

func safeList(fn func(context.Context) ([]pkcs12store.Identity, error), ctx context.Context, label string) (ids []pkcs12store.Identity, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: panic while listing %s: %v\n%s", label, r, string(debug.Stack()))
			ids = nil
			err = fmt.Errorf("panic while listing %s", label)
		}
	}()
	return fn(ctx)
}

func NewApp(build BuildInfo) (*App, error) {
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
		BuildInfo: BuildInfo{
			Version:   nonEmpty(build.Version, "dev"),
			Commit:    nonEmpty(build.Commit, "unknown"),
			BuildDate: nonEmpty(build.BuildDate, "unknown"),
		},
		ReleasePageURL: appnet.LatestReleasePageURL,
	}

	// Initial load
	ids, _ := store.List(context.Background())
	app.SetIdentities(ids)

	if len(ids) == 0 {
		app.ShowWizard = true
		app.CurrentScreen = ScreenWizard
	}

	return app, nil
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
