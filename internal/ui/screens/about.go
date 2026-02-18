package screens

import (
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/net"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/icons"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/widgets"
)

const (
	sourceCodeURL = "https://github.com/vocdoni/vocsign"
	vocdoniURL    = "https://vocdoni.io"
)

type AboutScreen struct {
	App   *app.App
	Theme *material.Theme

	OpenReleases widget.Clickable
	OpenSource   widget.Clickable
	OpenVocdoni  widget.Clickable
}

func NewAboutScreen(a *app.App, th *material.Theme) *AboutScreen {
	return &AboutScreen{
		App:   a,
		Theme: th,
	}
}

func (s *AboutScreen) Layout(gtx layout.Context) layout.Dimensions {
	if s.OpenReleases.Clicked(gtx) {
		widgets.OpenURL(net.LatestReleasePageURL)
	}
	if s.OpenSource.Clicked(gtx) {
		widgets.OpenURL(sourceCodeURL)
	}
	if s.OpenVocdoni.Clicked(gtx) {
		widgets.OpenURL(vocdoniURL)
	}

	return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
		return widgets.ConstrainMaxWidth(gtx, unit.Dp(920), func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.IconLabel(gtx, s.Theme, icons.IconAbout, "About VocSign", s.Theme.Palette.ContrastBg, unit.Sp(24))
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(material.Body1(s.Theme, "VocSign is an open-source desktop signer built by Vocdoni Global.").Layout),
							layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
							layout.Rigid(material.Body2(s.Theme, "License: GNU AGPLv3. The source code is public and auditable.").Layout),
							layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										btn := widgets.SecondaryButton(s.Theme, &s.OpenReleases, "Releases")
										return btn.Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										btn := widgets.SecondaryButton(s.Theme, &s.OpenSource, "Source Code")
										return btn.Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										btn := widgets.SecondaryButton(s.Theme, &s.OpenVocdoni, "vocdoni.io")
										return btn.Layout(gtx)
									}),
								)
							}),
						)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(material.Body1(s.Theme, "What is Vocdoni?").Layout),
							layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
							layout.Rigid(material.Body2(s.Theme, "Vocdoni develops open digital participation infrastructure for voting, governance and collective decision-making.").Layout),
							layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
							layout.Rigid(material.Body2(s.Theme, "Its vision is to make secure, verifiable and censorship-resistant participation accessible to any organization or community.").Layout),
						)
					})
				}),
			)
		})
	})
}
