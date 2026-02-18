//go:build cgo

package systemstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unsafe"

	"github.com/miekg/pkcs11"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
)

type NSSStore struct {
	LibPath    string
	ProfileDir string
	Label      string
}

type nssIdentityDTO struct {
	FriendlyName string `json:"friendlyName"`
	CertPEM      string `json:"certPem"`
	LibPath      string `json:"libPath"`
	ProfileDir   string `json:"profileDir"`
	Slot         uint   `json:"slot"`
	IDHex        string `json:"idHex"`
}

func DiscoverNSSStores(ctx context.Context) []*NSSStore {
	var stores []*NSSStore
	seen := make(map[string]struct{})

	libPath := findNSSLib()
	if libPath == "" {
		return nil
	}

	addStore := func(profileDir, label string) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if profileDir == "" {
			return
		}
		profileDir = filepath.Clean(profileDir)
		// Accept both modern cert9.db and legacy cert8.db
		hasCert9 := func() bool {
			_, err := os.Stat(filepath.Join(profileDir, "cert9.db"))
			return err == nil
		}()
		hasCert8 := func() bool {
			_, err := os.Stat(filepath.Join(profileDir, "cert8.db"))
			return err == nil
		}()
		if !hasCert9 && !hasCert8 {
			return
		}
		if _, ok := seen[profileDir]; ok {
			return
		}
		seen[profileDir] = struct{}{}
		stores = append(stores, &NSSStore{
			LibPath:    libPath,
			ProfileDir: profileDir,
			Label:      label,
		})
	}

	home, _ := os.UserHomeDir()

	// 1. Common NSS DB
	nssDB := filepath.Join(home, ".pki", "nssdb")
	addStore(nssDB, "System NSS")

	// 2. Firefox profiles (active profile first, then fallbacks).
	for i, profileDir := range discoverFirefoxProfileDirs() {
		label := fmt.Sprintf("Firefox Profile %d", i+1)
		if i == 0 {
			label = "Firefox Active Profile"
		}
		addStore(profileDir, label)
	}

	// 3. Chromium-family NSS DBs — covers Chrome, Brave, Edge, Opera, Vivaldi, etc.
	for _, base := range chromiumBaseDirs() {
		addStore(base, "Browser NSS")
		entries, _ := os.ReadDir(base)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			n := entry.Name()
			if n == "Default" || strings.HasPrefix(n, "Profile ") || strings.HasPrefix(n, "Guest Profile") {
				addStore(filepath.Join(base, n), "Browser Profile: "+n)
			}
		}
	}

	// 4. System-wide NSS locations commonly used on Linux
	if runtime.GOOS != "windows" {
		for _, sysPath := range []string{"/etc/pki/nssdb", "/etc/nssdb"} {
			if _, err := os.Stat(filepath.Join(sysPath, "cert9.db")); err == nil {
				addStore(sysPath, "System NSS")
			}
		}
	}

	// 5. Aggressive walk: look for cert9.db/cert8.db under all likely roots.
	walkRoots := uniqueExistingDirs(
		filepath.Join(home, ".pki"),
		filepath.Join(home, ".mozilla"),
		filepath.Join(home, ".thunderbird"),
		filepath.Join(home, ".librewolf"),
		filepath.Join(home, ".waterfox"),
		filepath.Join(home, ".var", "app"),  // flatpak user data
		filepath.Join(home, "snap"),         // snap user data
		filepath.Join(home, ".local", "share"),
		localAppDataDir(),
		appDataDir(),
	)
	if runtime.GOOS == "darwin" {
		walkRoots = append(walkRoots, filepath.Join(home, "Library", "Application Support"))
	}
	if runtime.GOOS == "linux" {
		walkRoots = append(walkRoots,
			"/etc/pki",
			"/etc/ssl",
		)
	}
	candidates := walkNSSCandidates(ctx, walkRoots, 7, 500)
	for _, dir := range candidates {
		addStore(dir, "Browser NSS")
	}

	return stores
}

func findNSSLib() string {
	for _, envName := range []string{"VOCSIGN_NSS_LIB", "NSS_LIB_PATH"} {
		if p := os.Getenv(envName); p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	if p := findNSSLibFromFirefoxCompatibility(); p != "" {
		return p
	}

	switch runtime.GOOS {
	case "windows":
		programFiles := os.Getenv("ProgramFiles")
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		paths := []string{
			filepath.Join(programFiles, "Mozilla Firefox", "softokn3.dll"),
			filepath.Join(programFilesX86, "Mozilla Firefox", "softokn3.dll"),
			filepath.Join(programFiles, "Mozilla Firefox", "nss3.dll"),
			filepath.Join(programFilesX86, "Mozilla Firefox", "nss3.dll"),
			"C:\\Program Files\\Mozilla Firefox\\softokn3.dll",
			"C:\\Program Files (x86)\\Mozilla Firefox\\softokn3.dll",
			"C:\\Program Files\\Mozilla Firefox\\nss3.dll",
			"C:\\Program Files (x86)\\Mozilla Firefox\\nss3.dll",
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	case "darwin":
		paths := []string{
			"/Applications/Firefox.app/Contents/MacOS/libsoftokn3.dylib",
			"/Applications/Firefox.app/Contents/MacOS/libnss3.dylib",
			"/usr/local/lib/libsoftokn3.dylib",
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	default:
		paths := []string{
			// Debian/Ubuntu multiarch
			"/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
			"/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so",
			"/usr/lib/i386-linux-gnu/libsoftokn3.so",
			"/usr/lib/aarch64-linux-gnu/libsoftokn3.so",
			"/usr/lib/arm-linux-gnueabihf/libsoftokn3.so",
			// Generic / Fedora / RHEL / Arch
			"/usr/lib/libsoftokn3.so",
			"/usr/lib64/libsoftokn3.so",
			"/usr/lib64/nss/libsoftokn3.so",
			// libnss3 fallback (some distros only ship this)
			"/usr/lib/x86_64-linux-gnu/libnss3.so",
			"/usr/lib/libnss3.so",
			"/usr/lib64/libnss3.so",
			// Firefox snap bundle
			"/snap/firefox/current/usr/lib/firefox/libsoftokn3.so",
			"/snap/firefox/current/usr/lib/firefox/libnss3.so",
			// Firefox flatpak bundle
			"/var/lib/flatpak/app/org.mozilla.firefox/current/active/files/lib/firefox/libsoftokn3.so",
			"/var/lib/flatpak/app/org.mozilla.firefox/current/active/files/lib/firefox/libnss3.so",
		}
		// Also check user-local flatpak
		if home, err := os.UserHomeDir(); err == nil {
			paths = append(paths,
				filepath.Join(home, ".local", "share", "flatpak", "app", "org.mozilla.firefox", "current", "active", "files", "lib", "firefox", "libsoftokn3.so"),
				filepath.Join(home, ".local", "share", "flatpak", "app", "org.mozilla.firefox", "current", "active", "files", "lib", "firefox", "libnss3.so"),
			)
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

func uniqueExistingDirs(dirs ...string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, d := range dirs {
		if d == "" {
			continue
		}
		d = filepath.Clean(d)
		if _, err := os.Stat(d); err != nil {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func walkNSSCandidates(ctx context.Context, roots []string, maxDepth int, limit int) []string {
	type void struct{}
	seen := make(map[string]void)
	var results []string
	for _, root := range roots {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		root = filepath.Clean(root)
		rootDepth := len(strings.Split(root, string(os.PathSeparator)))
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return context.Canceled
			default:
			}
			depth := len(strings.Split(path, string(os.PathSeparator))) - rootDepth
			if depth > maxDepth {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			name := d.Name()
			if name != "cert9.db" && name != "cert8.db" {
				return nil
			}
			dir := filepath.Dir(path)
			if _, ok := seen[dir]; ok {
				return nil
			}
			seen[dir] = void{}
			results = append(results, dir)
			if limit > 0 && len(results) >= limit {
				return context.Canceled
			}
			return nil
		})
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	return results
}

func (s *NSSStore) List(ctx context.Context) ([]pkcs12store.Identity, error) {
	return s.listViaWorker(ctx)
}

func (s *NSSStore) listViaWorker(ctx context.Context) ([]pkcs12store.Identity, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}
	cmd := exec.CommandContext(ctx, exe,
		"--nss-scan-worker",
		"--lib", s.LibPath,
		"--profile", s.ProfileDir,
		"--label", s.Label,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nss worker failed for %s (%s): %w stderr=%s", s.Label, s.ProfileDir, err, strings.TrimSpace(stderr.String()))
	}
	var payload []nssIdentityDTO
	if err := json.Unmarshal(stdout, &payload); err != nil {
		return nil, fmt.Errorf("decode nss worker output for %s (%s): %w raw=%q stderr=%s", s.Label, s.ProfileDir, err, string(stdout), strings.TrimSpace(stderr.String()))
	}
	out := make([]pkcs12store.Identity, 0, len(payload))
	for _, dto := range payload {
		block, _ := pem.Decode([]byte(dto.CertPEM))
		if block == nil || len(block.Bytes) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		keyID, err := hex.DecodeString(dto.IDHex)
		if err != nil {
			continue
		}
		out = append(out, pkcs12store.Identity{
			ID:             fmt.Sprintf("nss:%s:%x", s.Label, pkcs12store.Fingerprint(cert)),
			FriendlyName:   dto.FriendlyName,
			Cert:           cert,
			Fingerprint256: pkcs12store.Fingerprint(cert),
			Signer: &pkcs12store.PKCS11Signer{
				LibPath:    dto.LibPath,
				ProfileDir: dto.ProfileDir,
				Slot:       dto.Slot,
				ID:         keyID,
				PublicKey:  cert.PublicKey,
			},
		})
	}
	return out, nil
}

func (s *NSSStore) listDirect(ctx context.Context) ([]pkcs12store.Identity, error) {
	log.Printf("DEBUG: Scanning NSS Store: %s (Profile: %s)", s.Label, s.ProfileDir)
	p := pkcs11.New(s.LibPath)
	if p == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 lib: %s", s.LibPath)
	}
	defer p.Destroy()

	os.Setenv("NSS_CONFIG_DIR", "sql:"+s.ProfileDir)

	params := fmt.Sprintf("configdir='sql:%s' certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly", s.ProfileDir)
	pByte := append([]byte(params), 0)
	pPtr := unsafe.Pointer(&pByte[0])

	err := p.Initialize(pkcs11.InitializeWithReserved(pPtr))
	if err != nil {
		log.Printf("DEBUG: NSS Initialize with reserved failed, trying plain: %v", err)
		if err2 := p.Initialize(); err2 != nil {
			return nil, fmt.Errorf("pkcs11 initialize failed: reserved=%v plain=%w", err, err2)
		}
	}
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Printf("DEBUG: GetSlotList failed: %v", err)
		return nil, err
	}
	log.Printf("DEBUG: Found %d PKCS#11 slots in %s", len(slots), s.Label)

	var identities []pkcs12store.Identity
	for _, slot := range slots {
		if ctx.Err() != nil {
			return identities, ctx.Err()
		}
		session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			log.Printf("DEBUG: OpenSession failed for slot %d: %v", slot, err)
			continue
		}

		func(slot uint) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ERROR: panic while scanning NSS slot %d in %s: %v\n%s", slot, s.Label, r, string(debug.Stack()))
				}
				if err := p.Logout(session); err != nil && err != pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN) {
					log.Printf("DEBUG: Logout failed for slot %d in %s: %v", slot, s.Label, err)
				}
				if err := p.CloseSession(session); err != nil {
					log.Printf("DEBUG: CloseSession failed for slot %d in %s: %v", slot, s.Label, err)
				}
			}()

			if err := p.Login(session, pkcs11.CKU_USER, ""); err != nil &&
				err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				log.Printf("DEBUG: Login failed for slot %d in %s: %v", slot, s.Label, err)
			}

			searchTemplate := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			}
			if err := p.FindObjectsInit(session, searchTemplate); err != nil {
				log.Printf("DEBUG: FindObjectsInit failed for slot %d in %s: %v", slot, s.Label, err)
				return
			}
			objHandles, _, err := p.FindObjects(session, 1000)
			if err != nil {
				log.Printf("DEBUG: FindObjects failed for slot %d in %s: %v", slot, s.Label, err)
				_ = p.FindObjectsFinal(session)
				return
			}
			if err := p.FindObjectsFinal(session); err != nil {
				log.Printf("DEBUG: FindObjectsFinal failed for slot %d in %s: %v", slot, s.Label, err)
			}
			log.Printf("DEBUG: Slot %d in %s has %d certificate objects", slot, s.Label, len(objHandles))

			for _, obj := range objHandles {
				attrs, err := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
					pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
					pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
				})
				if err != nil {
					log.Printf("DEBUG: GetAttributeValue failed for obj %v in slot %d (%s): %v", obj, slot, s.Label, err)
					continue
				}
				if len(attrs) < 3 {
					log.Printf("DEBUG: GetAttributeValue returned %d attrs for obj %v in slot %d (%s), expected 3", len(attrs), obj, slot, s.Label)
					continue
				}

				certDER := attrs[0].Value
				label := string(attrs[1].Value)
				ckaID := attrs[2].Value
				if len(certDER) == 0 {
					continue
				}

				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					continue
				}
				if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
					continue
				}
				if cert.KeyUsage != 0 && (cert.KeyUsage&x509.KeyUsageDigitalSignature == 0) && (cert.KeyUsage&x509.KeyUsageContentCommitment == 0) {
					continue
				}

				log.Printf("DEBUG: Found candidate certificate in %s: %s (Subject: %s)", s.Label, label, cert.Subject.CommonName)

				privTemplate := []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
					pkcs11.NewAttribute(pkcs11.CKA_ID, ckaID),
				}
				if err := p.FindObjectsInit(session, privTemplate); err != nil {
					log.Printf("DEBUG: FindObjectsInit(private key) failed for slot %d in %s: %v", slot, s.Label, err)
					continue
				}
				privObjs, _, err := p.FindObjects(session, 1)
				if err != nil {
					log.Printf("DEBUG: FindObjects(private key) failed for slot %d in %s: %v", slot, s.Label, err)
					_ = p.FindObjectsFinal(session)
					continue
				}
				if err := p.FindObjectsFinal(session); err != nil {
					log.Printf("DEBUG: FindObjectsFinal(private key) failed for slot %d in %s: %v", slot, s.Label, err)
				}
				if len(privObjs) == 0 {
					continue
				}

				log.Printf("DEBUG:   Found matching private key for %s in %s", label, s.Label)
				signer := &pkcs12store.PKCS11Signer{
					LibPath:    s.LibPath,
					ProfileDir: s.ProfileDir,
					Slot:       slot,
					ID:         ckaID,
					PublicKey:  cert.PublicKey,
				}

				displayName := label
				if cert.Subject.CommonName != "" {
					displayName = cert.Subject.CommonName
				}
				identities = append(identities, pkcs12store.Identity{
					ID:             fmt.Sprintf("nss:%s:%x", s.Label, pkcs12store.Fingerprint(cert)),
					FriendlyName:   fmt.Sprintf("[%s] %s", s.Label, displayName),
					Cert:           cert,
					Fingerprint256: pkcs12store.Fingerprint(cert),
					Signer:         signer,
				})
			}
		}(slot)
	}

	return identities, nil
}

func identitiesToDTO(ids []pkcs12store.Identity) ([]nssIdentityDTO, error) {
	out := make([]nssIdentityDTO, 0, len(ids))
	for _, id := range ids {
		signer, ok := id.Signer.(*pkcs12store.PKCS11Signer)
		if !ok || id.Cert == nil {
			continue
		}
		out = append(out, nssIdentityDTO{
			FriendlyName: id.FriendlyName,
			CertPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.Cert.Raw})),
			LibPath:      signer.LibPath,
			ProfileDir:   signer.ProfileDir,
			Slot:         signer.Slot,
			IDHex:        hex.EncodeToString(signer.ID),
		})
	}
	return out, nil
}

// PKCS11Signer and related types moved to pkcs12store package to avoid circular dependency.
