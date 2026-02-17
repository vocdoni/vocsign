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
		return []string{
			filepath.Join(home, ".mozilla", "firefox"),
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
		}
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
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "key4.db")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "key3.db")); err == nil {
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
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	return ""
}

func localAppDataDir() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Local")
}

func appDataDir() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	if v := os.Getenv("APPDATA"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Roaming")
}
