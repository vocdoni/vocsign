package screens

import (
	"image"
	"image/color"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
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

	status := s.App.UpdateStatusSnapshot()

	return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
		return widgets.ConstrainMaxWidth(gtx, unit.Dp(680), func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,

				// Hero icon
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutHeroIcon(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),

				// App name + version
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutTitle(gtx, status.CurrentVersion)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),

				// Tagline
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					l := material.Label(s.Theme, unit.Sp(15), "Open-source desktop signer built by Vocdoni Global")
					l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
					l.Alignment = text.Middle
					return l.Layout(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),

				// License badge
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutBadge(gtx, "GNU AGPLv3 — source code is public and auditable")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(32)}.Layout),

				// Link buttons row
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutLinkButtons(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(36)}.Layout),

				// Vocdoni info card
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutInfoCard(gtx)
				}),
			)
		})
	})
}

func (s *AboutScreen) layoutHeroIcon(gtx layout.Context) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		bgColor := color.NRGBA{R: 0xEE, G: 0xF3, B: 0xFF, A: 0xFF}
		sz := gtx.Dp(unit.Dp(80))
		gtx.Constraints.Min = image.Point{X: sz, Y: sz}
		gtx.Constraints.Max = gtx.Constraints.Min
		paint.FillShape(gtx.Ops, bgColor, clip.Ellipse{Max: image.Point{X: sz, Y: sz}}.Op(gtx.Ops))
		return layout.UniformInset(unit.Dp(18)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			isz := gtx.Dp(unit.Dp(44))
			gtx.Constraints.Min = image.Point{X: isz, Y: isz}
			gtx.Constraints.Max = gtx.Constraints.Min
			return icons.IconVocSign.Layout(gtx, s.Theme.Palette.ContrastBg)
		})
	})
}

func (s *AboutScreen) layoutTitle(gtx layout.Context, version string) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Label(s.Theme, unit.Sp(30), "VocSign")
				l.Font.Weight = font.Bold
				l.Color = s.Theme.Palette.Fg
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if version == "" {
					return layout.Dimensions{}
				}
				return widgets.Border(gtx, s.Theme.Palette.ContrastBg, func(gtx layout.Context) layout.Dimensions {
					return widgets.CustomCard(gtx, color.NRGBA{R: 0xEE, G: 0xF3, B: 0xFF, A: 0xFF}, unit.Dp(6), func(gtx layout.Context) layout.Dimensions {
						l := material.Label(s.Theme, unit.Sp(12), "v"+version)
						l.Color = s.Theme.Palette.ContrastBg
						l.Font.Weight = font.Medium
						return l.Layout(gtx)
					})
				})
			}),
		)
	})
}

func (s *AboutScreen) layoutBadge(gtx layout.Context, text string) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = 0
		return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
			return widgets.CustomCard(gtx, color.NRGBA{R: 0xF6, G: 0xF8, B: 0xFC, A: 0xFF}, unit.Dp(6), func(gtx layout.Context) layout.Dimensions {
				l := material.Label(s.Theme, unit.Sp(12), text)
				l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
				return l.Layout(gtx)
			})
		})
	})
}

func (s *AboutScreen) layoutLinkButtons(gtx layout.Context) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = 0
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return s.linkButton(gtx, &s.OpenReleases, icons.IconLaunch, "Releases")
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return s.linkButton(gtx, &s.OpenSource, icons.IconLaunch, "Source Code")
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return s.linkButton(gtx, &s.OpenVocdoni, icons.IconLaunch, "vocdoni.io")
			}),
		)
	})
}

func (s *AboutScreen) linkButton(gtx layout.Context, click *widget.Clickable, icon *widget.Icon, label string) layout.Dimensions {
	return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
		return material.Clickable(gtx, click, func(gtx layout.Context) layout.Dimensions {
			return widgets.CustomCard(gtx, widgets.ColorSurface, unit.Dp(10), func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if icon == nil {
							return layout.Dimensions{}
						}
						sz := gtx.Dp(unit.Dp(16))
						gtx.Constraints.Min = image.Point{X: sz, Y: sz}
						gtx.Constraints.Max = gtx.Constraints.Min
						return icon.Layout(gtx, s.Theme.Palette.ContrastBg)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Label(s.Theme, unit.Sp(13), label)
						l.Color = s.Theme.Palette.ContrastBg
						l.Font.Weight = font.Medium
						return l.Layout(gtx)
					}),
				)
			})
		})
	})
}

func (s *AboutScreen) layoutInfoCard(gtx layout.Context) layout.Dimensions {
	return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
		return widgets.CustomCard(gtx, widgets.ColorSurface, unit.Dp(24), func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						sz := gtx.Dp(unit.Dp(36))
						gtx.Constraints.Min = image.Point{X: sz, Y: sz}
						gtx.Constraints.Max = gtx.Constraints.Min
						bgColor := color.NRGBA{R: 0xEE, G: 0xF3, B: 0xFF, A: 0xFF}
						paint.FillShape(gtx.Ops, bgColor, clip.Ellipse{Max: image.Point{X: sz, Y: sz}}.Op(gtx.Ops))
						return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							isz := gtx.Dp(unit.Dp(20))
							gtx.Constraints.Min = image.Point{X: isz, Y: isz}
							gtx.Constraints.Max = gtx.Constraints.Min
							return icons.IconAbout.Layout(gtx, s.Theme.Palette.ContrastBg)
						})
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						l := material.Label(s.Theme, unit.Sp(16), "What is Vocdoni?")
						l.Font.Weight = font.Bold
						l.Color = s.Theme.Palette.Fg
						l.Alignment = text.Middle
						return l.Layout(gtx)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					l := material.Body2(s.Theme, "Vocdoni develops open digital participation infrastructure for voting, governance and collective decision-making.")
					l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
					l.Alignment = text.Middle
					return l.Layout(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					l := material.Body2(s.Theme, "Its vision is to make secure, verifiable and censorship-resistant participation accessible to any organization or community.")
					l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
					l.Alignment = text.Middle
					return l.Layout(gtx)
				}),
			)
		})
	})
}
