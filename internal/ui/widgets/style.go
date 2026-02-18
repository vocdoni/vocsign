package widgets

import (
	"image/color"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

const (
	DefaultPageMaxWidth = unit.Dp(1180)
)

type BannerTone int

const (
	BannerInfo BannerTone = iota
	BannerSuccess
	BannerWarning
	BannerError
)

func ConstrainMaxWidth(gtx layout.Context, max unit.Dp, w layout.Widget) layout.Dimensions {
	return layout.N.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		maxPx := gtx.Dp(max)
		if gtx.Constraints.Max.X > maxPx {
			gtx.Constraints.Max.X = maxPx
		}
		if gtx.Constraints.Min.X > gtx.Constraints.Max.X {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
		}
		return w(gtx)
	})
}

func CenterInAvailable(gtx layout.Context, w layout.Widget) layout.Dimensions {
	return layout.Stack{Alignment: layout.Center}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			return layout.Dimensions{Size: gtx.Constraints.Max}
		}),
		layout.Stacked(w),
	)
}

func Section(gtx layout.Context, bg color.NRGBA, w layout.Widget) layout.Dimensions {
	return Border(gtx, ColorBorder, func(gtx layout.Context) layout.Dimensions {
		return Card(gtx, bg, w)
	})
}

func Banner(gtx layout.Context, th *material.Theme, tone BannerTone, text string) layout.Dimensions {
	if text == "" {
		return layout.Dimensions{}
	}
	var (
		bg = color.NRGBA{R: 0xEE, G: 0xF3, B: 0xFF, A: 0xFF}
		fg = color.NRGBA{R: 0x1E, G: 0x40, B: 0xAF, A: 0xFF}
	)
	switch tone {
	case BannerSuccess:
		bg = color.NRGBA{R: 0xE8, G: 0xF5, B: 0xE9, A: 0xFF}
		fg = ColorSuccess
	case BannerWarning:
		bg = color.NRGBA{R: 0xFF, G: 0xF4, B: 0xE5, A: 0xFF}
		fg = ColorWarning
	case BannerError:
		bg = color.NRGBA{R: 0xFD, G: 0xEA, B: 0xEA, A: 0xFF}
		fg = ColorError
	}
	return Border(gtx, fg, func(gtx layout.Context) layout.Dimensions {
		return CustomCard(gtx, bg, unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
			l := material.Body2(th, text)
			l.Color = fg
			return l.Layout(gtx)
		})
	})
}

func Tag(gtx layout.Context, th *material.Theme, text string, fg color.NRGBA) layout.Dimensions {
	return Border(gtx, fg, func(gtx layout.Context) layout.Dimensions {
		return CustomCard(gtx, color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}, unit.Dp(4), func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(th, text)
			l.Color = fg
			l.Font.Weight = font.Bold
			return l.Layout(gtx)
		})
	})
}

func PrimaryButton(th *material.Theme, c *widget.Clickable, text string) material.ButtonStyle {
	btn := material.Button(th, c, text)
	btn.Background = th.Palette.ContrastBg
	btn.Color = th.Palette.ContrastFg
	btn.TextSize = unit.Sp(14)
	return btn
}

func SecondaryButton(th *material.Theme, c *widget.Clickable, text string) material.ButtonStyle {
	btn := material.Button(th, c, text)
	btn.Background = color.NRGBA{R: 0xE8, G: 0xED, B: 0xF5, A: 0xFF}
	btn.Color = th.Palette.Fg
	btn.TextSize = unit.Sp(14)
	return btn
}

func DangerButton(th *material.Theme, c *widget.Clickable, text string) material.ButtonStyle {
	btn := material.Button(th, c, text)
	btn.Background = ColorError
	btn.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	btn.TextSize = unit.Sp(14)
	return btn
}

func EmptyState(gtx layout.Context, th *material.Theme, title, subtitle string) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body1(th, title)
				l.Color = th.Palette.Fg
				l.Font.Weight = font.Bold
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(th, subtitle)
				l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
				return l.Layout(gtx)
			}),
		)
	})
}
