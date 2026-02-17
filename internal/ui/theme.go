package ui

import (
	"image/color"

	"gioui.org/unit"
	"gioui.org/widget/material"
)

func NewTheme() *material.Theme {
	th := material.NewTheme()
	
	// Modern Deep Teal / Indigo Theme with refined colors
	th.Palette.Bg = color.NRGBA{R: 0xF8, G: 0xF9, B: 0xFB, A: 0xFF} // Soft cool grey
	th.Palette.Fg = color.NRGBA{R: 0x1A, G: 0x1C, B: 0x1E, A: 0xFF}
	
	// Primary: Indigo 600
	th.Palette.ContrastBg = color.NRGBA{R: 0x3F, G: 0x51, B: 0xB5, A: 0xFF}
	th.Palette.ContrastFg = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	
	th.TextSize = unit.Sp(16)
	
	return th
}

// Global UI constants
var (
	ColorSuccess = color.NRGBA{R: 0x2E, G: 0x7D, B: 0x32, A: 0xFF} // Green 800
	ColorError   = color.NRGBA{R: 0xD3, G: 0x2F, B: 0x2F, A: 0xFF} // Red 700
	ColorWarning = color.NRGBA{R: 0xED, G: 0x6C, B: 0x02, A: 0xFF} // Orange 800
	ColorSurface = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	ColorBorder  = color.NRGBA{R: 0xE0, G: 0xE4, B: 0xE8, A: 0xFF}
	ColorAccent  = color.NRGBA{R: 0x00, G: 0xBC, B: 0xD4, A: 0xFF} // Cyan
	ColorDivider = color.NRGBA{R: 0xED, G: 0xF1, B: 0xF5, A: 0xFF}
)
