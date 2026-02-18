package main

import (
	"log"
	"os"

	gioapp "gioui.org/app"
	"gioui.org/unit"

	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/ui"
)

func main() {
	vocsignApp, err := app.NewApp()
	if err != nil {
		log.Fatalf("Failed to initialize app: %v", err)
	}

	go func() {
		w := new(gioapp.Window)
		w.Option(
			gioapp.Title("VocSign"),
			gioapp.Size(unit.Dp(1280), unit.Dp(920)),
		)
		if err := ui.Run(w, vocsignApp); err != nil {
			log.Fatalf("UI failed: %v", err)
		}
		os.Exit(0)
	}()

	gioapp.Main()
}
