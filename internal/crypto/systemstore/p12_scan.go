package systemstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
)

// FindPKCS12Candidates walks common user locations to find .p12/.pfx files.
// It skips files larger than 5 MB and older than 10 years, and caps results.
func FindPKCS12Candidates(ctx context.Context, maxDepth int, limit int) []string {
	maxDepth = envInt("VOCSIGN_P12_MAX_DEPTH", maxDepth)
	limit = envInt("VOCSIGN_P12_MAX_RESULTS", limit)
	maxSizeBytes := int64(envInt("VOCSIGN_P12_MAX_SIZE_MB", 5)) * 1024 * 1024
	if maxSizeBytes <= 0 {
		maxSizeBytes = 5 * 1024 * 1024
	}
	maxAgeYears := envInt("VOCSIGN_P12_MAX_AGE_YEARS", 10)

	home, _ := os.UserHomeDir()

	roots := p12ScanRoots(home)

	if extra := os.Getenv("VOCSIGN_P12_EXTRA_ROOTS"); extra != "" {
		for _, r := range strings.Split(extra, string(os.PathListSeparator)) {
			if r = strings.TrimSpace(r); r != "" {
				roots = append(roots, r)
			}
		}
	}

	type void struct{}
	seen := make(map[string]void)
	var results []string
	cutoff := time.Now().AddDate(-maxAgeYears, 0, 0)

	for _, root := range roots {
		if root == "" {
			continue
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}
		root = filepath.Clean(root)
		rootDepth := pathDepth(root)

		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return context.Canceled
			default:
			}

			if d.IsDir() {
				depth := pathDepth(path) - rootDepth
				if depth > maxDepth {
					return filepath.SkipDir
				}
				// Skip directories that will never contain user certificates
				if shouldSkipDir(d.Name(), depth) {
					return filepath.SkipDir
				}
				return nil
			}

			if !hasP12Extension(d.Name()) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Size() == 0 || info.Size() > maxSizeBytes {
				return nil
			}
			if info.ModTime().Before(cutoff) {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}
			seen[path] = void{}
			results = append(results, path)
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

// p12ScanRoots returns the ordered list of directories to search for .p12/.pfx files.
func p12ScanRoots(home string) []string {
	roots := []string{
		// Most likely locations first
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Documents"),

		// PKI / certificate specific dirs
		filepath.Join(home, ".pki"),
		filepath.Join(home, ".ssl"),
		filepath.Join(home, ".certs"),
		filepath.Join(home, ".certificates"),
		filepath.Join(home, "certs"),
		filepath.Join(home, "certificates"),
		filepath.Join(home, ".gnupg"),  // some tools store PKCS#12 here

		// XDG user dirs
		xdgUserDir("XDG_DOCUMENTS_DIR", filepath.Join(home, "Documents")),
		xdgUserDir("XDG_DESKTOP_DIR", filepath.Join(home, "Desktop")),
		xdgUserDir("XDG_DOWNLOAD_DIR", filepath.Join(home, "Downloads")),

		// Config / app data (browser exports, admin tools)
		filepath.Join(home, ".config"),
		filepath.Join(home, ".local", "share"),

		// Flatpak / snap home areas
		filepath.Join(home, ".var", "app"),
		filepath.Join(home, "snap"),
	}

	// OS-specific additions
	switch runtime.GOOS {
	case "windows":
		local := localAppDataDir()
		roaming := appDataDir()
		roots = append(roots,
			filepath.Join(local, "Microsoft", "Crypto"),
			filepath.Join(roaming, "Microsoft", "Crypto"),
			filepath.Join(local, "Microsoft", "SystemCertificates"),
			filepath.Join(roaming, "Microsoft", "SystemCertificates"),
		)
	case "darwin":
		roots = append(roots,
			filepath.Join(home, "Library", "Keychains"),
			filepath.Join(home, "Library", "Application Support"),
		)
	default:
		// Linux: also check /etc/ssl and /etc/pki for admin-placed files
		roots = append(roots,
			"/etc/ssl/private",
			"/etc/pki/tls/private",
			"/etc/pki/ca-trust/source",
		)
	}

	return roots
}

// shouldSkipDir returns true for directories that are very unlikely to contain
// user certificate files and would waste time traversing.
func shouldSkipDir(name string, depth int) bool {
	// Always skip these regardless of depth
	alwaysSkip := map[string]bool{
		"node_modules": true,
		".git":         true,
		".svn":         true,
		".hg":          true,
		"__pycache__":  true,
		".cache":       true,
		"Cache":        true,
		"cache":        true,
		"CacheStorage": true,
		"Code Cache":   true,
		"GPUCache":     true,
		"ShaderCache":  true,
		"DawnCache":    true,
		"logs":         true,
		"Logs":         true,
		"log":          true,
		"tmp":          true,
		"temp":         true,
		"Temp":         true,
		"trash":        true,
		".Trash":       true,
		"Trash":        true,
		"thumbnails":   true,
		"Thumbnails":   true,
		"icons":        true,
		"Icons":        true,
		"fonts":        true,
		"Fonts":        true,
		"locale":       true,
		"locales":      true,
		"i18n":         true,
	}
	if alwaysSkip[name] {
		return true
	}
	// Skip deep hidden directories (depth > 1) that are not pki/cert related
	if depth > 1 && strings.HasPrefix(name, ".") {
		lower := strings.ToLower(name)
		certRelated := strings.Contains(lower, "cert") ||
			strings.Contains(lower, "pki") ||
			strings.Contains(lower, "ssl") ||
			strings.Contains(lower, "key") ||
			strings.Contains(lower, "crypto") ||
			strings.Contains(lower, "firefox") ||
			strings.Contains(lower, "mozilla") ||
			strings.Contains(lower, "thunderbird") ||
			strings.Contains(lower, "librewolf") ||
			strings.Contains(lower, "waterfox")
		if !certRelated {
			return true
		}
	}
	return false
}

func hasP12Extension(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".p12" || ext == ".pfx"
}

// pathDepth returns the number of components in a cleaned path.
func pathDepth(p string) int {
	p = filepath.Clean(p)
	if p == "." || p == string(filepath.Separator) {
		return 0
	}
	return strings.Count(p, string(filepath.Separator))
}

// xdgUserDir returns the value of an XDG env variable, falling back to fallback.
func xdgUserDir(env, fallback string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return fallback
}

// ParsePKCS12Metadata tries to read a PKCS#12 file and returns an Identity.
// Returns ErrPKCS12PasswordRequired when the file is password-protected.
var ErrPKCS12PasswordRequired = fmt.Errorf("pkcs12 password required")

func ParsePKCS12Metadata(path, password string) (pkcs12store.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return pkcs12store.Identity{}, err
	}
	defer f.Close()

	signer, cert, chain, err := pkcs12store.ParsePKCS12(f, password)
	if err != nil {
		if isPKCS12PasswordError(err) {
			return pkcs12store.Identity{}, ErrPKCS12PasswordRequired
		}
		return pkcs12store.Identity{}, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}

	return pkcs12store.Identity{
		ID:             "file:" + path,
		FriendlyName:   fmt.Sprintf("File: %s", filepath.Base(path)),
		Cert:           cert,
		Chain:          chain,
		Fingerprint256: pkcs12store.Fingerprint(cert),
		Signer:         signer,
	}, nil
}

func isPKCS12PasswordError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "password") || strings.Contains(msg, "mac could not be verified")
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
