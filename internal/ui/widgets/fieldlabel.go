package widgets

import (
	"image/color"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// FieldSource indicates where a field's value comes from.
type FieldSource int

const (
	FieldManual   FieldSource = iota // user must fill in
	FieldFromCert                    // auto-filled from certificate
)

// FieldLabel renders a label with a source indicator caption.
func FieldLabel(gtx layout.Context, th *material.Theme, label string, source FieldSource) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, label)
			l.Font.Weight = font.Medium
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			var text string
			var clr color.NRGBA
			switch source {
			case FieldFromCert:
				text = "(from certificate)"
				clr = ColorSuccess
			case FieldManual:
				text = "(please fill in)"
				clr = ColorWarning
			}
			l := material.Caption(th, text)
			l.Color = clr
			l.TextSize = unit.Sp(10)
			return l.Layout(gtx)
		}),
	)
}
