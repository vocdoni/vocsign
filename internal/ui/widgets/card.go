package widgets

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
)

// Card draws a rounded rectangle background with a shadow-like appearance
func Card(gtx layout.Context, bg color.NRGBA, w layout.Widget) layout.Dimensions {
	return CustomCard(gtx, bg, unit.Dp(20), w)
}

func CustomCard(gtx layout.Context, bg color.NRGBA, inset unit.Dp, w layout.Widget) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			rr := clip.RRect{
				Rect: image.Rectangle{Max: gtx.Constraints.Min},
				NE:   gtx.Dp(12), NW: gtx.Dp(12), SE: gtx.Dp(12), SW: gtx.Dp(12),
			}
			shape := rr.Op(gtx.Ops)
			paint.FillShape(gtx.Ops, bg, shape)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(inset).Layout(gtx, w)
		}),
	)
}

// Border draws a rounded border around a widget
func Border(gtx layout.Context, clr color.NRGBA, w layout.Widget) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			rr := clip.RRect{
				Rect: image.Rectangle{Max: gtx.Constraints.Min},
				NE:   gtx.Dp(12), NW: gtx.Dp(12), SE: gtx.Dp(12), SW: gtx.Dp(12),
			}
			paint.FillShape(gtx.Ops, clr, clip.Stroke{
				Path:  rr.Path(gtx.Ops),
				Width: float32(gtx.Dp(1)),
			}.Op())
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(w),
	)
}

// VerticalDivider draws a thin horizontal line
func VerticalDivider(gtx layout.Context, clr color.NRGBA) layout.Dimensions {
	d := image.Point{X: gtx.Constraints.Min.X, Y: gtx.Dp(1)}
	dr := image.Rectangle{Max: d}
	paint.FillShape(gtx.Ops, clr, clip.Rect(dr).Op())
	return layout.Dimensions{Size: d}
}
