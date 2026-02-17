package widgets

import (
	"fmt"
	"os/exec"
	"runtime"
)

func OpenURL(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	}
	if err != nil {
		fmt.Printf("DEBUG: Failed to open URL: %v\n", err)
	}
}
