package screens

import (
	"context"
	"fmt"
	"io"
	"log"
	"runtime/debug"
	"strings"

	"gioui.org/io/clipboard"
	"gioui.org/io/transfer"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/jwsverify"
	"github.com/vocdoni/gofirma/vocsign/internal/net"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/icons"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/widgets"
)

type OpenRequestScreen struct {
	App   *app.App
	Theme *material.Theme

	URLEditor   widget.Editor
	FetchButton widget.Clickable
	PasteButton widget.Clickable
}

func NewOpenRequestScreen(a *app.App, th *material.Theme) *OpenRequestScreen {
	s := &OpenRequestScreen{
		App:   a,
		Theme: th,
	}
	s.URLEditor.SingleLine = true
	return s
}

func (s *OpenRequestScreen) Layout(gtx layout.Context) layout.Dimensions {
	if s.FetchButton.Clicked(gtx) {
		url := strings.TrimSpace(s.URLEditor.Text())
		if url != "" {
			s.App.FetchStatus = "Connecting to server..."
			s.App.ReqError = nil

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("ERROR: panic while fetching request: %v\n%s", r, string(debug.Stack()))
						s.App.FetchStatus = "Unexpected Error: could not process request"
						s.App.ReqError = fmt.Errorf("panic while processing request: %v", r)
						s.App.Invalidate()
					}
				}()

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
		gtx.Execute(clipboard.ReadCmd{Tag: s})
	}

	for {
		ev, ok := gtx.Event(transfer.TargetFilter{Target: s, Type: "application/text"})
		if !ok {
			break
		}
		switch ev := ev.(type) {
		case transfer.DataEvent:
			rc := ev.Open()
			data, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				s.App.FetchStatus = "Clipboard Error: could not read clipboard text"
				s.App.ReqError = err
				break
			}
			txt := strings.TrimSpace(string(data))
			if txt == "" {
				s.App.FetchStatus = "Clipboard is empty"
				s.App.ReqError = nil
				break
			}
			s.URLEditor.SetText(txt)
			s.App.FetchStatus = "Signing URL pasted from clipboard"
			s.App.ReqError = nil
		case transfer.CancelEvent:
			s.App.FetchStatus = "Clipboard paste canceled"
			s.App.ReqError = nil
		}
	}

	return layout.UniformInset(unit.Dp(6)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
			return widgets.ConstrainMaxWidth(gtx, unit.Dp(860), func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Bottom: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return widgets.IconLabel(gtx, s.Theme, icons.IconOpenRequest, "Open Signing Request", s.Theme.Palette.ContrastBg, unit.Sp(24))
						})
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(material.Body1(s.Theme, "Paste the URL provided by the organizer.").Layout),
								layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Flexed(1, material.Editor(s.Theme, &s.URLEditor, "https://...").Layout),
										layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											btn := widgets.SecondaryButton(s.Theme, &s.PasteButton, "Paste")
											return btn.Layout(gtx)
										}),
									)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									btn := widgets.PrimaryButton(s.Theme, &s.FetchButton, "Fetch Proposal")
									return btn.Layout(gtx)
								}),
							)
						})
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if s.App.FetchStatus == "" {
							return layout.Dimensions{}
						}
						return layout.Inset{Top: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							tone := statusTone(s.App.FetchStatus)
							return widgets.Banner(gtx, s.Theme, tone, s.App.FetchStatus)
						})
					}),
				)
			})
		})
	})
}

func statusTone(status string) widgets.BannerTone {
	lower := strings.ToLower(status)
	switch {
	case strings.Contains(lower, "failed"), strings.Contains(lower, "error"):
		return widgets.BannerError
	case strings.Contains(lower, "ready"), strings.Contains(lower, "pasted"):
		return widgets.BannerSuccess
	default:
		return widgets.BannerInfo
	}
}
