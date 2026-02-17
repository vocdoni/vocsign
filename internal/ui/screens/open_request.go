package screens

import (
	"context"
	"strings"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/atotto/clipboard"
	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/jwsverify"
	"github.com/vocdoni/gofirma/vocsign/internal/net"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/icons"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/widgets"
)

type OpenRequestScreen struct {
	App   *app.App
	Theme *material.Theme
	
	List widget.List 
	
	URLEditor    widget.Editor
	StatusEditor widget.Editor
	FetchButton  widget.Clickable
	PasteButton  widget.Clickable
}

func NewOpenRequestScreen(a *app.App, th *material.Theme) *OpenRequestScreen {
	s := &OpenRequestScreen{
		App:   a,
		Theme: th,
	}
	s.List.Axis = layout.Vertical
	s.URLEditor.SingleLine = true
	s.StatusEditor.ReadOnly = true
	return s
}

func (s *OpenRequestScreen) Layout(gtx layout.Context) layout.Dimensions {
	if s.FetchButton.Clicked(gtx) {
		url := strings.TrimSpace(s.URLEditor.Text())
		if url != "" {
			s.App.FetchStatus = "Connecting to server..."
			s.App.ReqError = nil
			
			go func() {
				ctx := context.Background()
				req, raw, err := net.Fetch(ctx, url)
				if err != nil {
					s.App.FetchStatus = "Connection Error: " + err.Error()
					s.App.ReqError = err
					return
				}
				
				s.App.FetchStatus = "Authenticating Request..."
				if err := jwsverify.Verify(req); err != nil {
					s.App.FetchStatus = "Security Validation Failed: " + err.Error()
					s.App.ReqError = err
				} else {
					s.App.FetchStatus = "Ready"
					s.App.CurrentReq = req
					s.App.RawReq = raw
					s.App.RequestURL = url
					s.App.CurrentScreen = app.ScreenRequestDetails
				}
				s.App.Invalidate()
			}()
		}
	}

	if s.PasteButton.Clicked(gtx) {
		if text, err := clipboard.ReadAll(); err == nil {
			s.URLEditor.SetText(text)
		}
	}

	if s.StatusEditor.Text() != s.App.FetchStatus {
		s.StatusEditor.SetText(s.App.FetchStatus)
	}

	return material.List(s.Theme, &s.List).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.Card(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.X = gtx.Dp(500)
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return widgets.IconLabel(gtx, s.Theme, icons.IconOpenRequest, "Paste the Signing URL provided by the organizer:", s.Theme.Palette.Fg, unit.Sp(16))
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, material.Editor(s.Theme, &s.URLEditor, "https://...").Layout),
									layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										btn := material.Button(s.Theme, &s.PasteButton, "Paste")
										btn.Background = widgets.ColorBorder
										btn.Color = s.Theme.Palette.Fg
										return btn.Layout(gtx)
									}),
								)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return material.Button(s.Theme, &s.FetchButton, "FETCH PROPOSAL").Layout(gtx)
							}),
						)
					})
				}),
				
				layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if s.App.FetchStatus == "" { return layout.Dimensions{} }
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return material.Body2(s.Theme, s.App.FetchStatus).Layout(gtx)
					})
				}),
			)
		})
	})
}
