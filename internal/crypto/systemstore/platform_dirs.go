package systemstore

import (
	"os"
	"path/filepath"
	"runtime"
)

// localAppDataDir returns the per-user local application data directory.
//
//   - Windows: %LOCALAPPDATA%  (e.g. C:\Users\Alice\AppData\Local)
//   - macOS:   ~/Library/Application Support
//   - Linux:   ~/.config
func localAppDataDir() string {
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return v
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "AppData", "Local")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config")
	}
}

// appDataDir returns the per-user roaming application data directory.
//
//   - Windows: %APPDATA%  (e.g. C:\Users\Alice\AppData\Roaming)
//   - macOS/Linux: same as localAppDataDir
func appDataDir() string {
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("APPDATA"); v != "" {
			return v
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "AppData", "Roaming")
	default:
		return localAppDataDir()
	}
}
