package ui

import (
	"image/color"

	"gioui.org/unit"
	"gioui.org/widget/material"
)

func NewTheme() *material.Theme {
	th := material.NewTheme()

	th.Palette.Bg = color.NRGBA{R: 0xF6, G: 0xF8, B: 0xFC, A: 0xFF}
	th.Palette.Fg = color.NRGBA{R: 0x17, G: 0x24, B: 0x3A, A: 0xFF}
	th.Palette.ContrastBg = color.NRGBA{R: 0x1E, G: 0x40, B: 0xAF, A: 0xFF}
	th.Palette.ContrastFg = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}

	th.TextSize = unit.Sp(16)

	return th
}
