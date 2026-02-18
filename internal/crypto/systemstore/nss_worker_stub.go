//go:build !cgo

package systemstore

import (
	"fmt"
	"os"
)

// RunNSSScanWorker is unavailable without cgo.
func RunNSSScanWorker(args []string) int {
	fmt.Fprintln(os.Stderr, "nss worker: unavailable (built without cgo)")
	return 2
}
