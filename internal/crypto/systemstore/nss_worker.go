//go:build cgo

package systemstore

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// RunNSSScanWorker handles the hidden CLI mode used to isolate NSS scanning.
// It returns an exit code and writes JSON payload to stdout on success.
func RunNSSScanWorker(args []string) int {
	fs := flag.NewFlagSet("nss-scan-worker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		libPath    string
		profileDir string
		label      string
	)
	fs.StringVar(&libPath, "lib", "", "PKCS#11 library path")
	fs.StringVar(&profileDir, "profile", "", "NSS profile directory")
	fs.StringVar(&label, "label", "Browser NSS", "store label")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "nss worker: parse args: %v\n", err)
		return 2
	}
	if libPath == "" || profileDir == "" {
		fmt.Fprintf(os.Stderr, "nss worker: --lib and --profile are required\n")
		return 2
	}

	store := &NSSStore{
		LibPath:    libPath,
		ProfileDir: profileDir,
		Label:      label,
	}
	ids, err := store.listDirect(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "nss worker: scan failed for %s (%s): %v\n", label, profileDir, err)
		return 1
	}
	payload, err := identitiesToDTO(ids)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nss worker: encode payload failed: %v\n", err)
		return 1
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(payload); err != nil {
		fmt.Fprintf(os.Stderr, "nss worker: write payload failed: %v\n", err)
		return 1
	}
	return 0
}
