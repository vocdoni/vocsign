//go:build cgo

package systemstore

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
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

func DiscoverNSSStores() []*NSSStore {
	var stores []*NSSStore
	seen := make(map[string]struct{})

	libPath := findNSSLib()
	if libPath == "" {
		return nil
	}

	addStore := func(profileDir, label string) {
		if profileDir == "" {
			return
		}
		profileDir = filepath.Clean(profileDir)
		if _, err := os.Stat(filepath.Join(profileDir, "cert9.db")); err != nil {
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

	// 3. Chromium/Brave NSS DBs (mostly Linux, with optional profile paths on other OSes).
	var chromiumBases []string
	switch runtime.GOOS {
	case "windows":
		localAppData := localAppDataDir()
		chromiumBases = []string{
			filepath.Join(localAppData, "Google", "Chrome", "User Data"),
			filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data"),
			filepath.Join(localAppData, "Chromium", "User Data"),
		}
	case "darwin":
		chromiumBases = []string{
			filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
			filepath.Join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, "Library", "Application Support", "Chromium"),
		}
	default:
		chromiumBases = []string{
			filepath.Join(home, ".config", "google-chrome"),
			filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, ".config", "chromium"),
			filepath.Join(home, "snap", "brave", "common", ".pki", "nssdb"),
		}
		snapPaths, _ := filepath.Glob(filepath.Join(home, "snap", "*", "current", ".pki", "nssdb"))
		chromiumBases = append(chromiumBases, snapPaths...)
		braveSnaps, _ := filepath.Glob(filepath.Join(home, "snap", "brave", "*", ".pki", "nssdb"))
		chromiumBases = append(chromiumBases, braveSnaps...)
	}
	for _, base := range chromiumBases {
		addStore(base, "Browser NSS")

		entries, _ := os.ReadDir(base)
		for _, entry := range entries {
			if entry.IsDir() && (entry.Name() == "Default" || strings.HasPrefix(entry.Name(), "Profile ")) {
				profileDir := filepath.Join(base, entry.Name())
				addStore(profileDir, "Browser Profile: "+entry.Name())
			}
		}
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
			"/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
			"/usr/lib/libsoftokn3.so",
			"/usr/lib64/libsoftokn3.so",
			"/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so",
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

func (s *NSSStore) List(ctx context.Context) ([]pkcs12store.Identity, error) {
	log.Printf("DEBUG: Scanning NSS Store: %s (Profile: %s)", s.Label, s.ProfileDir)
	p := pkcs11.New(s.LibPath)
	if p == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 lib: %s", s.LibPath)
	}

	os.Setenv("NSS_CONFIG_DIR", "sql:"+s.ProfileDir)
	_ = p.Finalize()

	params := fmt.Sprintf("configdir='sql:%s' certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly", s.ProfileDir)
	pByte := append([]byte(params), 0)
	pPtr := unsafe.Pointer(&pByte[0])

	err := p.Initialize(pkcs11.InitializeWithReserved(pPtr))
	if err != nil {
		log.Printf("DEBUG: NSS Initialize with reserved failed, trying plain: %v", err)
		_ = p.Initialize()
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
		session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			log.Printf("DEBUG: OpenSession failed for slot %d: %v", slot, err)
			continue
		}

		_ = p.Login(session, pkcs11.CKU_USER, "")

		p.FindObjectsInit(session, []*pkcs11.Attribute{})
		objHandles, _, err := p.FindObjects(session, 1000)
		p.FindObjectsFinal(session)

		if err != nil {
			log.Printf("DEBUG: FindObjects failed for slot %d: %v", slot, err)
			p.CloseSession(session)
			continue
		}
		log.Printf("DEBUG: Slot %d in %s has %d objects", slot, s.Label, len(objHandles))

		for _, obj := range objHandles {
			classAttr, err := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			})
			if err != nil || len(classAttr[0].Value) == 0 {
				continue
			}

			// Use first byte for class check (standard values are small)
			class := uint32(classAttr[0].Value[0])
			if class != uint32(pkcs11.CKO_CERTIFICATE) {
				continue
			}

			attrs, err := p.GetAttributeValue(session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil {
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

			p.FindObjectsInit(session, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_ID, ckaID),
			})
			privObjs, _, _ := p.FindObjects(session, 1)
			p.FindObjectsFinal(session)

			var signer crypto.Signer
			if len(privObjs) > 0 {
				log.Printf("DEBUG:   Found matching private key for %s in %s", label, s.Label)
				signer = &pkcs12store.PKCS11Signer{
					LibPath:    s.LibPath,
					ProfileDir: s.ProfileDir,
					Slot:       slot,
					ID:         ckaID,
					PublicKey:  cert.PublicKey,
				}
			}

			if signer == nil {
				continue
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
		p.CloseSession(session)
	}

	return identities, nil
}

// PKCS11Signer and related types moved to pkcs12store package to avoid circular dependency.
