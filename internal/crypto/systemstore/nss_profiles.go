//go:build cgo

package systemstore

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type firefoxProfile struct {
	relPath    string
	absPath    string
	isDefault  bool
	isRelative bool
	locked     bool
	modTime    int64
}

type firefoxInstallState struct {
	defaultPath string
	locked      bool
}

func firefoxBaseDirs() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return []string{filepath.Join(appData, "Mozilla", "Firefox")}
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "Firefox")}
	default:
		bases := []string{
			// Standard installs
			filepath.Join(home, ".mozilla", "firefox"),
			// Snap (Ubuntu)
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
			// Flatpak
			filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
			// ESR flatpak
			filepath.Join(home, ".var", "app", "org.mozilla.firefox_esr", ".mozilla", "firefox"),
			// LibreWolf flatpak
			filepath.Join(home, ".var", "app", "io.gitlab.librewolf-community", ".librewolf"),
			// LibreWolf native
			filepath.Join(home, ".librewolf"),
			// Waterfox native
			filepath.Join(home, ".waterfox"),
			// Waterfox flatpak
			filepath.Join(home, ".var", "app", "net.waterfox.waterfox", ".waterfox"),
			// Tor Browser (uses Firefox profile format)
			filepath.Join(home, ".local", "share", "torbrowser", "tbb", "x86_64", "tor-browser", "Browser", "TorBrowser", "Data", "Browser"),
			filepath.Join(home, "tor-browser", "Browser", "TorBrowser", "Data", "Browser"),
			// Thunderbird (also uses NSS)
			filepath.Join(home, ".thunderbird"),
			filepath.Join(home, "snap", "thunderbird", "common", ".thunderbird"),
			filepath.Join(home, ".var", "app", "org.mozilla.Thunderbird", ".thunderbird"),
		}
		// Also pick up any snap that looks like a Firefox variant
		if snapGlobs, err := filepath.Glob(filepath.Join(home, "snap", "firefox*", "common", ".mozilla", "firefox")); err == nil {
			bases = append(bases, snapGlobs...)
		}
		return bases
	}
}

// chromiumBaseDirs returns base config directories for all Chromium-family browsers.
func chromiumBaseDirs() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		local := localAppDataDir()
		roaming := appDataDir()
		return []string{
			filepath.Join(local, "Google", "Chrome", "User Data"),
			filepath.Join(local, "Google", "Chrome SxS", "User Data"), // Canary
			filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"),
			filepath.Join(local, "Chromium", "User Data"),
			filepath.Join(local, "Microsoft", "Edge", "User Data"),
			filepath.Join(local, "Opera Software", "Opera Stable"),
			filepath.Join(local, "Opera Software", "Opera GX Stable"),
			filepath.Join(local, "Vivaldi", "User Data"),
			filepath.Join(roaming, "Opera Software", "Opera Stable"),
		}
	case "darwin":
		appSupport := filepath.Join(home, "Library", "Application Support")
		return []string{
			filepath.Join(appSupport, "Google", "Chrome"),
			filepath.Join(appSupport, "Google", "Chrome Canary"),
			filepath.Join(appSupport, "BraveSoftware", "Brave-Browser"),
			filepath.Join(appSupport, "Chromium"),
			filepath.Join(appSupport, "Microsoft Edge"),
			filepath.Join(appSupport, "com.operasoftware.Opera"),
			filepath.Join(appSupport, "Vivaldi"),
		}
	default:
		cfg := filepath.Join(home, ".config")
		bases := []string{
			filepath.Join(cfg, "google-chrome"),
			filepath.Join(cfg, "google-chrome-beta"),
			filepath.Join(cfg, "google-chrome-unstable"),
			filepath.Join(cfg, "BraveSoftware", "Brave-Browser"),
			filepath.Join(cfg, "BraveSoftware", "Brave-Browser-Beta"),
			filepath.Join(cfg, "BraveSoftware", "Brave-Browser-Nightly"),
			filepath.Join(cfg, "chromium"),
			filepath.Join(cfg, "microsoft-edge"),
			filepath.Join(cfg, "microsoft-edge-beta"),
			filepath.Join(cfg, "microsoft-edge-dev"),
			filepath.Join(cfg, "opera"),
			filepath.Join(cfg, "vivaldi"),
			filepath.Join(cfg, "yandex-browser"),
			filepath.Join(cfg, "thorium"),
			filepath.Join(cfg, "ungoogled-chromium"),
			// Snap paths
			filepath.Join(home, "snap", "brave", "common", ".config", "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, "snap", "chromium", "common", "chromium"),
		}
		// Generic snap chromium-family glob
		if snapGlobs, err := filepath.Glob(filepath.Join(home, "snap", "chromium*", "common", "chromium")); err == nil {
			bases = append(bases, snapGlobs...)
		}
		// Flatpak paths
		flatpakBases := []string{
			filepath.Join(home, ".var", "app", "com.google.Chrome", "config", "google-chrome"),
			filepath.Join(home, ".var", "app", "com.google.ChromeDev", "config", "google-chrome-unstable"),
			filepath.Join(home, ".var", "app", "com.brave.Browser", "config", "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, ".var", "app", "org.chromium.Chromium", "config", "chromium"),
			filepath.Join(home, ".var", "app", "com.microsoft.Edge", "config", "microsoft-edge"),
			filepath.Join(home, ".var", "app", "com.opera.Opera", "config", "opera"),
			filepath.Join(home, ".var", "app", "com.vivaldi.Vivaldi", "config", "vivaldi"),
		}
		bases = append(bases, flatpakBases...)
		return bases
	}
}

func discoverFirefoxProfileDirs() []string {
	var ordered []string
	seen := make(map[string]struct{})

	add := func(p string) {
		if p == "" {
			return
		}
		clean := filepath.Clean(p)
		if _, ok := seen[clean]; ok {
			return
		}
		if !isFirefoxProfileDir(clean) {
			return
		}
		seen[clean] = struct{}{}
		ordered = append(ordered, clean)
	}

	for _, base := range firefoxBaseDirs() {
		iniPath := filepath.Join(base, "profiles.ini")
		profiles, installStates := parseFirefoxProfilesINI(iniPath)
		activePath := resolveFirefoxActiveProfile(profiles, installStates)
		if activePath != "" {
			add(activePath)
		}

		sort.SliceStable(profiles, func(i, j int) bool {
			if profiles[i].isDefault != profiles[j].isDefault {
				return profiles[i].isDefault
			}
			return profiles[i].modTime > profiles[j].modTime
		})
		for _, p := range profiles {
			add(p.absPath)
		}

		// Fallback: walk the base dir for any profile-shaped subdirectory
		entries, _ := os.ReadDir(base)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			add(filepath.Join(base, entry.Name()))
		}
	}
	return ordered
}

func isFirefoxProfileDir(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "cert9.db")); err != nil {
		// Also accept legacy cert8.db-only profiles
		if _, err2 := os.Stat(filepath.Join(dir, "cert8.db")); err2 != nil {
			return false
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "key4.db")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "key3.db")); err == nil {
		return true
	}
	// Accept cert9.db alone (some minimal profiles have no key db yet)
	if _, err := os.Stat(filepath.Join(dir, "cert9.db")); err == nil {
		return true
	}
	return false
}

func parseFirefoxProfilesINI(iniPath string) ([]firefoxProfile, []firefoxInstallState) {
	f, err := os.Open(iniPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	baseDir := filepath.Dir(iniPath)
	profilesBySection := make(map[string]*firefoxProfile)
	installStateBySection := make(map[string]*firefoxInstallState)
	section := ""

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch {
		case strings.HasPrefix(section, "profile"):
			p := profilesBySection[section]
			if p == nil {
				p = &firefoxProfile{isRelative: true}
				profilesBySection[section] = p
			}
			switch key {
			case "path":
				p.relPath = val
				p.absPath = val
			case "isrelative":
				p.isRelative = val == "1"
			case "default":
				p.isDefault = val == "1"
			}
		case strings.HasPrefix(section, "install"):
			s := installStateBySection[section]
			if s == nil {
				s = &firefoxInstallState{}
				installStateBySection[section] = s
			}
			switch key {
			case "default":
				s.defaultPath = val
			case "locked":
				s.locked = val == "1"
			}
		}
	}

	var profiles []firefoxProfile
	for _, p := range profilesBySection {
		if p.relPath == "" {
			continue
		}
		if p.isRelative {
			p.absPath = filepath.Join(baseDir, p.relPath)
		}
		p.absPath = filepath.Clean(p.absPath)
		if st, err := os.Stat(p.absPath); err == nil {
			p.modTime = st.ModTime().Unix()
		}
		p.locked = firefoxProfileLocked(p.absPath)
		profiles = append(profiles, *p)
	}

	var states []firefoxInstallState
	for _, s := range installStateBySection {
		states = append(states, *s)
	}
	return profiles, states
}

func firefoxProfileLocked(profileDir string) bool {
	if _, err := os.Stat(filepath.Join(profileDir, "parent.lock")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(profileDir, "lock")); err == nil {
		return true
	}
	if info, err := os.Lstat(filepath.Join(profileDir, "lock")); err == nil && (info.Mode()&os.ModeSymlink) != 0 {
		return true
	}
	return false
}

func resolveFirefoxActiveProfile(profiles []firefoxProfile, installStates []firefoxInstallState) string {
	byRelPath := make(map[string]string)
	for _, p := range profiles {
		byRelPath[p.relPath] = p.absPath
	}
	for _, state := range installStates {
		if !state.locked || state.defaultPath == "" {
			continue
		}
		if p, ok := byRelPath[state.defaultPath]; ok && isFirefoxProfileDir(p) {
			return p
		}
	}
	for _, p := range profiles {
		if p.locked && isFirefoxProfileDir(p.absPath) {
			return p.absPath
		}
	}
	for _, p := range profiles {
		if p.isDefault && isFirefoxProfileDir(p.absPath) {
			return p.absPath
		}
	}
	var newest string
	var newestTS int64
	for _, p := range profiles {
		if !isFirefoxProfileDir(p.absPath) {
			continue
		}
		if p.modTime > newestTS {
			newestTS = p.modTime
			newest = p.absPath
		}
	}
	return newest
}

func findNSSLibFromFirefoxCompatibility() string {
	for _, profile := range discoverFirefoxProfileDirs() {
		compat := filepath.Join(profile, "compatibility.ini")
		f, err := os.Open(compat)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		lastPlatformDir := ""
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "LastPlatformDir=") {
				lastPlatformDir = strings.TrimSpace(strings.TrimPrefix(line, "LastPlatformDir="))
				break
			}
		}
		_ = f.Close()
		if lastPlatformDir == "" {
			continue
		}
		candidates := []string{
			filepath.Join(lastPlatformDir, "softokn3.dll"),
			filepath.Join(lastPlatformDir, "nss3.dll"),
			filepath.Join(lastPlatformDir, "libsoftokn3.dylib"),
			filepath.Join(lastPlatformDir, "libnss3.dylib"),
			filepath.Join(lastPlatformDir, "libsoftokn3.so"),
			filepath.Join(lastPlatformDir, "libnss3.so"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	return ""
}

