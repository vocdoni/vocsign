package widgets

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

func IconText(th *material.Theme, icon *widget.Icon, text string, iconColor color.NRGBA) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if icon == nil {
					return layout.Dimensions{}
				}
				return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					sz := gtx.Dp(unit.Dp(24))
					gtx.Constraints.Min = image.Point{X: sz, Y: sz}
					gtx.Constraints.Max = gtx.Constraints.Min
					return icon.Layout(gtx, iconColor)
				})
			}),
			layout.Rigid(material.Body1(th, text).Layout),
		)
	}
}

// IconLabel renders an icon followed by a label
func IconLabel(gtx layout.Context, th *material.Theme, icon *widget.Icon, text string, clr color.NRGBA, size unit.Sp) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if icon == nil { return layout.Dimensions{} }
			return layout.Inset{Right: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				// Icons should be prominently larger
				sz := gtx.Dp(unit.Dp(float32(size) * 2.0))
				if sz < gtx.Dp(24) { sz = gtx.Dp(24) }
				gtx.Constraints.Min = image.Point{X: sz, Y: sz}
				gtx.Constraints.Max = gtx.Constraints.Min
				return icon.Layout(gtx, clr)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Label(th, size, text)
			l.Color = clr
			return l.Layout(gtx)
		}),
	)
}
