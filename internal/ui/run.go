package ui

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	_ "image/png"

	gioapp "gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/assets"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/icons"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/screens"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/widgets"
	"gioui.org/x/explorer"
)

func Run(w *gioapp.Window, a *app.App) error {
	fmt.Printf("DEBUG: VocSign Run loop started\n")
	a.Explorer = explorer.NewExplorer(w)
	a.Invalidate = w.Invalidate
	th := NewTheme()
	var ops op.Ops

	// Decode Logo
	img, _, err := image.Decode(bytes.NewReader(assets.LogoPNG))
	var logoOp paint.ImageOp
	if err == nil {
		logoOp = paint.NewImageOp(img)
	}

	// Initialize screens
	certScreen := screens.NewCertificatesScreen(a, th)
	openReqScreen := screens.NewOpenRequestScreen(a, th)
	reqDetailsScreen := screens.NewRequestDetailsScreen(a, th)
	auditScreen := screens.NewAuditScreen(a, th)
	wizardScreen := screens.NewWizardScreen(a, th)

	// Navigation state
	var (
		tabCert  widget.Clickable
		tabOpen  widget.Clickable
		tabAudit widget.Clickable
		logoClick widget.Clickable
	)

	lastScreen := a.CurrentScreen

	for {
		e := w.Event()
		// if _, ok := e.(gioapp.FrameEvent); !ok { fmt.Printf("DEBUG: UI Event: %T\n", e) }
		a.Explorer.ListenEvents(e)
		switch e := e.(type) {
		case gioapp.DestroyEvent:
			return e.Err
		case gioapp.FrameEvent:
			// log.Printf("DEBUG: FrameEvent received")
			gtx := gioapp.NewContext(&ops, e)

			// Handle Navigation
			if tabCert.Clicked(gtx) {
				a.CurrentScreen = app.ScreenCertificates
			}
			if tabOpen.Clicked(gtx) {
				a.CurrentScreen = app.ScreenOpenRequest
			}
			if tabAudit.Clicked(gtx) {
				a.CurrentScreen = app.ScreenAudit
			}
			if logoClick.Clicked(gtx) {
				widgets.OpenURL("https://vocdoni.io")
			}

			// Screen transition logic
			if a.CurrentScreen != lastScreen {
				if a.CurrentScreen == app.ScreenWizard {
					wizardScreen.Reset()
				}
				lastScreen = a.CurrentScreen
			}

			// Determine current screen
			var current layout.Widget
			switch a.CurrentScreen {
			case app.ScreenCertificates:
				current = certScreen.Layout
			case app.ScreenOpenRequest:
				current = openReqScreen.Layout
			case app.ScreenRequestDetails:
				current = reqDetailsScreen.Layout
			case app.ScreenAudit:
				current = auditScreen.Layout
			case app.ScreenWizard:
				current = wizardScreen.Layout
			default:
				current = openReqScreen.Layout
			}

			// Main Background & App Border
			layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
					return widgets.Card(gtx, th.Palette.Bg, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{
							Axis: layout.Vertical,
						}.Layout(gtx,
							// Navigation Bar (Hide in Wizard)
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if a.CurrentScreen == app.ScreenWizard {
									return layout.Dimensions{}
								}
								return layout.Stack{}.Layout(gtx,
									layout.Expanded(func(gtx layout.Context) layout.Dimensions {
										widgets.Card(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} })
										return layout.Dimensions{Size: gtx.Constraints.Min}
									}),
									layout.Stacked(func(gtx layout.Context) layout.Dimensions {
										return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													return widgets.IconLabel(gtx, th, icons.IconVocSign, "VocSign", th.Palette.ContrastBg, unit.Sp(20))
												}),
												layout.Rigid(layout.Spacer{Width: unit.Dp(32)}.Layout),
												
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													bg := color.NRGBA{A: 0}
													fg := th.Palette.Fg
													if a.CurrentScreen == app.ScreenOpenRequest || a.CurrentScreen == app.ScreenRequestDetails {
														bg = th.Palette.ContrastBg
														fg = th.Palette.ContrastFg
													}
													return material.Clickable(gtx, &tabOpen, func(gtx layout.Context) layout.Dimensions {
														return widgets.Border(gtx, color.NRGBA{A: 0}, func(gtx layout.Context) layout.Dimensions {
															return widgets.CustomCard(gtx, bg, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
																gtx.Constraints.Min.X = gtx.Dp(140)
																return widgets.IconLabel(gtx, th, icons.IconOpenRequest, "Open Request", fg, unit.Sp(14))
															})
														})
													})
												}),
												layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													bg := color.NRGBA{A: 0}
													fg := th.Palette.Fg
													if a.CurrentScreen == app.ScreenCertificates {
														bg = th.Palette.ContrastBg
														fg = th.Palette.ContrastFg
													}
													return material.Clickable(gtx, &tabCert, func(gtx layout.Context) layout.Dimensions {
														return widgets.CustomCard(gtx, bg, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
															gtx.Constraints.Min.X = gtx.Dp(140)
															return widgets.IconLabel(gtx, th, icons.IconCertificates, "My Certificates", fg, unit.Sp(14))
														})
													})
												}),
												layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													bg := color.NRGBA{A: 0}
													fg := th.Palette.Fg
													if a.CurrentScreen == app.ScreenAudit {
														bg = th.Palette.ContrastBg
														fg = th.Palette.ContrastFg
													}
													return material.Clickable(gtx, &tabAudit, func(gtx layout.Context) layout.Dimensions {
														return widgets.CustomCard(gtx, bg, unit.Dp(8), func(gtx layout.Context) layout.Dimensions {
															gtx.Constraints.Min.X = gtx.Dp(140)
															return widgets.IconLabel(gtx, th, icons.IconAudit, "Audit Log", fg, unit.Sp(14))
														})
													})
												}),
											)
										})
									}),
								)
							}),
							// Separator
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if a.CurrentScreen == app.ScreenWizard {
									return layout.Dimensions{}
								}
								return widgets.VerticalDivider(gtx, color.NRGBA{R: 0xED, G: 0xF1, B: 0xF5, A: 0xFF})
							}),
							// Screen Content
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.UniformInset(unit.Dp(24)).Layout(gtx, current)
							}),
							// Footer with Logo
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle, Spacing: layout.SpaceEnd}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											if err != nil {
												return layout.Dimensions{}
											}
											return material.Clickable(gtx, &logoClick, func(gtx layout.Context) layout.Dimensions {
												gtx.Constraints.Max.X = gtx.Dp(120) // Bigger logo
												gtx.Constraints.Max.Y = gtx.Dp(40)
												return widget.Image{
													Src: logoOp,
													Fit: widget.Contain,
												}.Layout(gtx)
											})
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											l := material.Caption(th, "Powered by Vocdoni Open Stack")
											l.Color = color.NRGBA{R: 0x66, G: 0x66, B: 0x66, A: 0xFF}
											return l.Layout(gtx)
										}),
									)
								})
							}),
						)
					})
				})
			})

			e.Frame(gtx.Ops)
		}
	}
}
