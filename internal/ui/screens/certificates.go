package screens

import (
	"context"
	"image/color"
	"strings"
	"time"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/certs"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/icons"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/widgets"
)

type CertificatesScreen struct {
	App   *app.App
	Theme *material.Theme

	List         widget.List
	DetailsList  widget.List
	WizardButton widget.Clickable

	DeleteButtons   map[string]*widget.Clickable
	Clickables      map[string]*widget.Clickable
	ConfirmDelete   widget.Clickable
	CancelDelete    widget.Clickable
	pendingDeleteID string

	selectedID   string
	selectedInfo certs.ExtractedInfo

	SubjectEditor widget.Editor
}

func NewCertificatesScreen(a *app.App, th *material.Theme) *CertificatesScreen {
	s := &CertificatesScreen{
		App:           a,
		Theme:         th,
		DeleteButtons: make(map[string]*widget.Clickable),
		Clickables:    make(map[string]*widget.Clickable),
	}
	s.List.Axis = layout.Vertical
	s.DetailsList.Axis = layout.Vertical
	s.SubjectEditor.ReadOnly = true
	return s
}

func (s *CertificatesScreen) Layout(gtx layout.Context) layout.Dimensions {
	identities := s.App.IdentitiesSnapshot()

	if s.WizardButton.Clicked(gtx) {
		s.App.CurrentScreen = app.ScreenWizard
	}

	for _, id := range identities {
		if btn, ok := s.DeleteButtons[id.ID]; ok && btn.Clicked(gtx) {
			s.pendingDeleteID = id.ID
		}
	}
	if s.ConfirmDelete.Clicked(gtx) && s.pendingDeleteID != "" {
		targetID := s.pendingDeleteID
		s.pendingDeleteID = ""
		go func() {
			ctx := context.Background()
			s.App.Store.Delete(ctx, targetID)
			ids, _ := s.App.Store.List(ctx)
			s.App.SetIdentities(ids)
			if s.selectedID == targetID {
				s.selectedID = ""
			}
			s.App.Invalidate()
		}()
	}
	if s.CancelDelete.Clicked(gtx) {
		s.pendingDeleteID = ""
	}

	var pendingName string
	if s.pendingDeleteID != "" {
		for _, id := range identities {
			if id.ID == s.pendingDeleteID {
				pendingName = id.FriendlyName
				break
			}
		}
	}

	// Group identities
	groups := groupedIdentities{}
	for _, id := range identities {
		info := certs.ExtractSpanishIdentity(id.Cert)
		if info.IsRepresentative {
			groups.Representation = append(groups.Representation, id)
		} else {
			groups.Personal = append(groups.Personal, id)
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return widgets.IconLabel(gtx, s.Theme, icons.IconCertificates, "Identity Wallet", s.Theme.Palette.ContrastBg, unit.Sp(24))
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := widgets.PrimaryButton(s.Theme, &s.WizardButton, "Import Certificate")
					return btn.Layout(gtx)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if s.pendingDeleteID == "" {
				return layout.Dimensions{}
			}
			return layout.Inset{Bottom: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return widgets.Border(gtx, widgets.ColorWarning, func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, material.Body2(s.Theme, "Delete certificate: "+pendingName+" ?").Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(s.Theme, &s.ConfirmDelete, "Delete")
								btn.Background = widgets.ColorError
								btn.TextSize = unit.Sp(12)
								return btn.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(s.Theme, &s.CancelDelete, "Cancel")
								btn.TextSize = unit.Sp(12)
								return btn.Layout(gtx)
							}),
						)
					})
				})
			})
		}),

		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				// Left Col: List
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.Y = gtx.Constraints.Max.Y
					return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
						var widgetsToRender []layout.Widget
						if len(groups.Personal) > 0 {
							widgetsToRender = append(widgetsToRender, func(gtx layout.Context) layout.Dimensions {
								return material.Caption(s.Theme, "PERSONAL CERTIFICATES").Layout(gtx)
							})
							for _, id := range groups.Personal {
								widgetsToRender = append(widgetsToRender, s.certificateRow(id))
							}
						}
						if len(groups.Representation) > 0 {
							if len(groups.Personal) > 0 {
								widgetsToRender = append(widgetsToRender, func(gtx layout.Context) layout.Dimensions {
									return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx)
								})
							}
							widgetsToRender = append(widgetsToRender, func(gtx layout.Context) layout.Dimensions {
								l := material.Caption(s.Theme, "REPRESENTATION CERTIFICATES")
								l.Color = widgets.ColorWarning
								return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, l.Layout)
							})
							for _, id := range groups.Representation {
								widgetsToRender = append(widgetsToRender, s.certificateRow(id))
							}
						}

						if len(widgetsToRender) == 0 {
							return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
								return widgets.EmptyState(gtx, s.Theme, "Wallet is empty", "Import a certificate to start signing.")
							})
						}

						return material.List(s.Theme, &s.List).Layout(gtx, len(widgetsToRender), func(gtx layout.Context, index int) layout.Dimensions {
							return widgetsToRender[index](gtx)
						})
					})
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(24)}.Layout),
				// Right Col: Details (Scrollable)
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					if s.selectedID == "" {
						gtx.Constraints.Min.Y = gtx.Constraints.Max.Y
						return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
							return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
								return widgets.EmptyState(gtx, s.Theme, "No certificate selected", "Choose one from the left panel to view details.")
							})
						})
					}

					return material.List(s.Theme, &s.DetailsList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
						return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								// Header
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									name := s.selectedInfo.Nom + " " + strings.Join(s.selectedInfo.Cognoms, " ")
									if strings.TrimSpace(name) == "" {
										name = s.selectedID
									}
									l := material.H6(s.Theme, name)
									l.Color = s.Theme.Palette.ContrastBg
									return l.Layout(gtx)
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),

								// Identification Section
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return s.propertySection(gtx, "IDENTIFICATION", []property{
										{"DNI/NIE", s.selectedInfo.DNI},
										{"Organization", s.selectedInfo.Organization},
										{"Organization ID", s.selectedInfo.OrganizationID},
									})
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),

								// Validity Section
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return s.propertySection(gtx, "VALIDITY", []property{
										{"Issuer", s.selectedInfo.Issuer},
										{"Expires", s.selectedInfo.ValidUntil},
										{"Status", certStatusLabel(s.findIdentity(s.selectedID))},
									})
								}),
								layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),

								// Type Section
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									txt := "Personal Identity"
									clr := widgets.ColorSuccess
									icon := icons.IconCheck
									if s.selectedInfo.IsRepresentative {
										txt = "Representative Entity"
										if s.selectedInfo.OrganizationID != "" {
											txt = "Representative (Org ID: " + s.selectedInfo.OrganizationID + ")"
										}
										clr = widgets.ColorWarning
										icon = icons.IconWarning
									}
									return widgets.Border(gtx, clr, func(gtx layout.Context) layout.Dimensions {
										return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return widgets.IconLabel(gtx, s.Theme, icon, txt, clr, unit.Sp(14))
										})
									})
								}),

								layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
								layout.Rigid(material.Caption(s.Theme, "RAW SUBJECT:").Layout),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									s.SubjectEditor.SetText(s.selectedInfo.RawSubject)
									return material.Editor(s.Theme, &s.SubjectEditor, "").Layout(gtx)
								}),
							)
						})
					})
				}),
			)
		}),
	)
}

func (s *CertificatesScreen) certificateRow(id pkcs12store.Identity) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if _, ok := s.Clickables[id.ID]; !ok {
			s.Clickables[id.ID] = &widget.Clickable{}
		}
		btn := s.Clickables[id.ID]
		if btn.Clicked(gtx) {
			s.selectedID = id.ID
			s.selectedInfo = certs.ExtractSpanishIdentity(id.Cert)
		}

		return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			bg := widgets.ColorSurface
			if s.selectedID == id.ID {
				bg = color.NRGBA{R: 0xEE, G: 0xF2, B: 0xFF, A: 0xFF}
			}

			return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
				return material.Clickable(gtx, btn, func(gtx layout.Context) layout.Dimensions {
					return widgets.Card(gtx, bg, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												l := material.Body1(s.Theme, id.FriendlyName)
												l.Font.Weight = font.Bold
												return l.Layout(gtx)
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												if !isExpired(id.Cert.NotAfter) {
													return layout.Dimensions{}
												}
												return widgets.Tag(gtx, s.Theme, "Expired", widgets.ColorWarning)
											}),
										)
									}),
									layout.Rigid(material.Caption(s.Theme, "Issuer: "+id.Cert.Issuer.CommonName).Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										info := certs.ExtractSpanishIdentity(id.Cert)
										txt := "Personal"
										clr := widgets.ColorSuccess
										if info.IsRepresentative {
											txt = "Representative"
											if info.OrganizationID != "" {
												txt = "Representative (Org ID: " + info.OrganizationID + ")"
											}
											clr = widgets.ColorWarning
										}
										l := material.Caption(s.Theme, txt)
										l.Color = clr
										return l.Layout(gtx)
									}),
								)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if _, ok := s.DeleteButtons[id.ID]; !ok {
									s.DeleteButtons[id.ID] = &widget.Clickable{}
								}
								btn := widgets.DangerButton(s.Theme, s.DeleteButtons[id.ID], "X")
								btn.TextSize = unit.Sp(11)
								return layout.Inset{Top: unit.Dp(2), Bottom: unit.Dp(2), Left: unit.Dp(2), Right: unit.Dp(2)}.Layout(gtx, btn.Layout)
							}),
						)
					})
				})
			})
		})
	}
}

func isExpired(notAfter time.Time) bool {
	return time.Now().After(notAfter)
}

func certStatusLabel(id *pkcs12store.Identity) string {
	if id == nil || id.Cert == nil {
		return ""
	}
	if isExpired(id.Cert.NotAfter) {
		return "Expired"
	}
	return "Valid"
}

func (s *CertificatesScreen) findIdentity(id string) *pkcs12store.Identity {
	for _, identity := range s.App.IdentitiesSnapshot() {
		if identity.ID == id {
			idCopy := identity
			return &idCopy
		}
	}
	return nil
}

type property struct {
	label string
	value string
}

func (s *CertificatesScreen) propertySection(gtx layout.Context, title string, props []property) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(s.Theme, title)
			l.Color = s.Theme.Palette.ContrastBg
			l.Font.Weight = font.Bold
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					var children []layout.FlexChild
					for _, p := range props {
						if p.value == "" {
							continue
						}
						p := p
						children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									gtx.Constraints.Min.X = gtx.Dp(100)
									return material.Body2(s.Theme, p.label+":").Layout(gtx)
								}),
								layout.Flexed(1, material.Body2(s.Theme, p.value).Layout),
							)
						}))
						children = append(children, layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout))
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
				})
			})
		}),
	)
}
