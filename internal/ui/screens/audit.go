package screens

import (
	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/storage"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/icons"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/widgets"
)

type AuditScreen struct {
	App   *app.App
	Theme *material.Theme
	
	List      widget.List
	Entries   []storage.AuditEntry
	Refresh   widget.Clickable
	
	Editors map[string]*widget.Editor 
}

func NewAuditScreen(a *app.App, th *material.Theme) *AuditScreen {
	s := &AuditScreen{
		App:     a,
		Theme:   th,
		Editors: make(map[string]*widget.Editor),
	}
	s.List.Axis = layout.Vertical
	s.RefreshEntries()
	return s
}

func (s *AuditScreen) RefreshEntries() {
	go func() {
		entries, err := s.App.AuditLogger.ReadAll()
		if err == nil {
			for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
				entries[i], entries[j] = entries[j], entries[i]
			}
			s.Entries = entries
		}
	}()
}

func (s *AuditScreen) Layout(gtx layout.Context) layout.Dimensions {
	if s.Refresh.Clicked(gtx) {
		s.RefreshEntries()
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return widgets.IconLabel(gtx, s.Theme, icons.IconAudit, "Signing History", s.Theme.Palette.Fg, unit.Sp(24))
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(s.Theme, &s.Refresh, "Refresh")
					btn.Background = s.Theme.Palette.ContrastBg
					return btn.Layout(gtx)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
		
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return material.List(s.Theme, &s.List).Layout(gtx, len(s.Entries), func(gtx layout.Context, index int) layout.Dimensions {
				entry := s.Entries[index]
				
				key := entry.RequestID + entry.Timestamp
				if _, ok := s.Editors[key]; !ok {
					e := &widget.Editor{ReadOnly: true}
					e.SetText(entry.RequestID)
					s.Editors[key] = e
				}
				
				return layout.Inset{Bottom: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return widgets.Card(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										statusTxt := "SUCCESS"
										statusClr := widgets.ColorSuccess
										icon := icons.IconCheck
										if entry.Status != "success" {
											statusTxt = "FAILED"
											statusClr = widgets.ColorError
											icon = icons.IconError
										}
										
										return widgets.Border(gtx, statusClr, func(gtx layout.Context) layout.Dimensions {
											return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												return widgets.IconLabel(gtx, s.Theme, icon, statusTxt, statusClr, unit.Sp(12))
											})
										})
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
									layout.Rigid(material.Caption(s.Theme, entry.Timestamp).Layout),
								)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								l := material.Body1(s.Theme, entry.ProposalTitle)
								l.Font.Weight = font.Bold
								return l.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
									layout.Rigid(material.Body2(s.Theme, "Signer: "+entry.SignerName).Layout),
									layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
									layout.Rigid(material.Body2(s.Theme, "DNI: "+entry.SignerDNI).Layout),
								)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(material.Caption(s.Theme, "Request ID: ").Layout),
									layout.Flexed(1, material.Editor(s.Theme, s.Editors[key], "").Layout),
								)
							}),
							layout.Rigid(material.Caption(s.Theme, "Target Host: "+entry.CallbackHost).Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if entry.Error != "" {
									return layout.Inset{Top: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return widgets.Border(gtx, widgets.ColorError, func(gtx layout.Context) layout.Dimensions {
											return layout.UniformInset(unit.Dp(8)).Layout(gtx, material.Caption(s.Theme, entry.Error).Layout)
										})
									})
								}
								return layout.Dimensions{}
							}),
						)
					})
				})
			})
		}),
	)
}
