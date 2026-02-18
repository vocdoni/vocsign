package screens

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"image/color"
	"runtime"
	"strings"
	"time"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/cades"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/certs"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
	"github.com/vocdoni/gofirma/vocsign/internal/model"
	"github.com/vocdoni/gofirma/vocsign/internal/net"
	"github.com/vocdoni/gofirma/vocsign/internal/storage"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/icons"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/widgets"
)

type RequestDetailsScreen struct {
	App   *app.App
	Theme *material.Theme

	SignButton widget.Clickable
	CertList   widget.List
	CertEnum   widget.Enum

	IDEditor     widget.Editor
	StatusEditor widget.Editor

	NomEditor     widget.Editor
	Cognom1Editor widget.Editor
	Cognom2Editor widget.Editor
	DNIEditor     widget.Editor
	BirthEditor   widget.Editor

	DocLinkButton    widget.Clickable
	PolicyLinkButton widget.Clickable

	MainList     widget.List
	LeftList     widget.List
	RightList    widget.List
	PostSignList widget.List

	lastSelectedCert string
	selectedInfo     certs.ExtractedInfo
	IsSigning        bool

	backButton widget.Clickable
}

func NewRequestDetailsScreen(a *app.App, th *material.Theme) *RequestDetailsScreen {
	s := &RequestDetailsScreen{
		App:   a,
		Theme: th,
	}
	s.CertList.Axis = layout.Vertical
	s.MainList.Axis = layout.Vertical
	s.LeftList.Axis = layout.Vertical
	s.RightList.Axis = layout.Vertical
	s.PostSignList.Axis = layout.Vertical

	s.IDEditor.ReadOnly = true
	s.StatusEditor.ReadOnly = true

	s.BirthEditor.SetText("1980-01-01")
	return s
}

func (s *RequestDetailsScreen) Layout(gtx layout.Context) layout.Dimensions {
	req := s.App.CurrentReq
	if req == nil {
		return material.Body1(s.Theme, "No request loaded").Layout(gtx)
	}

	if s.App.SignResponse != nil {
		return material.List(s.Theme, &s.PostSignList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
			return s.layoutPostSign(gtx)
		})
	}

	if s.IDEditor.Text() != req.RequestID {
		s.IDEditor.SetText(req.RequestID)
	}

	if s.DocLinkButton.Clicked(gtx) {
		widgets.OpenURL(req.Proposal.FullText.URL)
	}
	if s.PolicyLinkButton.Clicked(gtx) && req.Policy != nil {
		widgets.OpenURL(req.Policy.URI)
	}

	if s.CertEnum.Value != s.lastSelectedCert {
		s.lastSelectedCert = s.CertEnum.Value
		if identity := s.findIdentity(s.CertEnum.Value); identity != nil {
			s.selectedInfo = certs.ExtractSpanishIdentity(identity.Cert)
			s.NomEditor.SetText(s.selectedInfo.Nom)
			if len(s.selectedInfo.Cognoms) >= 1 {
				s.Cognom1Editor.SetText(s.selectedInfo.Cognoms[0])
			} else {
				s.Cognom1Editor.SetText("")
			}
			if len(s.selectedInfo.Cognoms) >= 2 {
				s.Cognom2Editor.SetText(s.selectedInfo.Cognoms[1])
			} else {
				s.Cognom2Editor.SetText("")
			}
			s.DNIEditor.SetText(s.selectedInfo.DNI)
		} else {
			s.selectedInfo = certs.ExtractedInfo{}
		}
	}

	if s.StatusEditor.Text() != s.App.SignStatus {
		s.StatusEditor.SetText(s.App.SignStatus)
	}

	if s.SignButton.Clicked(gtx) && !s.IsSigning {
		certID := s.CertEnum.Value
		if certID != "" {
			identity := s.findIdentity(certID)
			if identity != nil {
				nom := strings.TrimSpace(s.NomEditor.Text())
				cognom1 := strings.TrimSpace(s.Cognom1Editor.Text())
				cognom2 := strings.TrimSpace(s.Cognom2Editor.Text())
				dni := strings.TrimSpace(s.DNIEditor.Text())
				if dni == "" {
					s.App.SignStatus = "Validation failed: signer ID/DNI is required"
				} else if nom == "" && cognom1 == "" && cognom2 == "" {
					s.App.SignStatus = "Validation failed: signer name is required"
				} else {
					s.IsSigning = true
					s.App.SignStatus = "Preparing legally compliant XML..."

					reqCopy := *req
					identityID := identity.ID
					identityCert := identity.Cert
					identityChain := identity.Chain
					isSystem := strings.HasPrefix(identityID, "nss:") || strings.HasPrefix(identityID, "os:")
					identitySigner := identity.Signer

					signerData := model.Signant{
						Nom:             nom,
						Cognom1:         cognom1,
						Cognom2:         cognom2,
						TipusIdentifica: "DNI",
						NumIdentifica:   dni,
						DataNaixement:   strings.TrimSpace(s.BirthEditor.Text()),
					}

					go func() {
						ctx := context.Background()
						defer func() { s.IsSigning = false }()

						var signer crypto.Signer
						var err error
						if isSystem {
							signer = identitySigner
						} else {
							signer, err = s.App.Store.Unlock(ctx, identityID)
						}

						if err != nil || signer == nil {
							if err == nil {
								err = fmt.Errorf("signer is nil")
							}
							s.App.SignStatus = "Unlock failed: " + err.Error()
							return
						}

						xmlBytes, err := model.GenerateILPXML(&reqCopy, signerData)
						if err != nil {
							s.App.SignStatus = "XML generation failed: " + err.Error()
							return
						}

						s.App.SignStatus = "Signing XML payload..."
						signatureDER, err := cades.SignDetached(ctx, signer, identityCert, identityChain, xmlBytes, cades.SignOpts{
							SigningTime: time.Now(),
							Policy:      reqCopy.Policy,
						})
						if err != nil {
							s.App.SignStatus = "Signing failed: " + err.Error()
							return
						}

						payloadHash := sha256.Sum256(xmlBytes)
						certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identityCert.Raw}))
						var chainPEM []string
						for _, c := range identityChain {
							chainPEM = append(chainPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
						}

						resp := &model.SignResponse{
							Version:                "1.0",
							RequestID:              reqCopy.RequestID,
							Nonce:                  reqCopy.Nonce,
							SignedAt:               time.Now().Format(time.RFC3339),
							PayloadCanonicalSHA256: base64.StdEncoding.EncodeToString(payloadHash[:]),
							SignatureFormat:        "CAdES-detached",
							SignatureDerBase64:     base64.StdEncoding.EncodeToString(signatureDER),
							SignerCertPEM:          certPEM,
							ChainPEM:               chainPEM,
							SignerXMLBase64:        base64.StdEncoding.EncodeToString(xmlBytes),
							Client: model.ClientInfo{
								App:     "vocsign",
								Version: "0.1.0",
								OS:      runtime.GOOS,
							},
						}

						s.App.SignStatus = "Submitting signature..."
						receipt, err := net.Submit(ctx, reqCopy.Callback.URL, resp)

						auditEntry := storage.AuditEntry{
							RequestID:       reqCopy.RequestID,
							ProposalTitle:   reqCopy.Proposal.Title,
							SignerName:      signerData.Nom + " " + signerData.Cognom1 + " " + signerData.Cognom2,
							SignerDNI:       signerData.NumIdentifica,
							CallbackHost:    "server",
							CertFingerprint: fmt.Sprintf("%x", pkcs12store.Fingerprint(identityCert)),
						}

						if err != nil {
							s.App.SignStatus = "Submission failed: " + err.Error()
							auditEntry.Status = "fail"
							auditEntry.Error = err.Error()
							s.App.AuditLogger.Log(auditEntry)
							return
						}

						s.App.SignResponse = resp
						auditEntry.Status = "success"
						auditEntry.ServerAckID = receipt.ReceiptID
						s.App.AuditLogger.Log(auditEntry)
						s.App.Invalidate()
					}()
				}
			}
		}
	}

	groups := groupedIdentities{}
	allIdentities := append([]pkcs12store.Identity{}, s.App.Identities...)
	allIdentities = append(allIdentities, s.App.SystemIdentities...)
	for _, id := range allIdentities {
		info := certs.ExtractSpanishIdentity(id.Cert)
		if info.IsRepresentative {
			groups.Representation = append(groups.Representation, id)
		} else {
			groups.Personal = append(groups.Personal, id)
		}
	}

	return material.List(s.Theme, &s.MainList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
		return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return widgets.IconLabel(gtx, s.Theme, icons.IconOpenRequest, "SIGN REQUEST", s.Theme.Palette.ContrastBg, unit.Sp(22))
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if s.backButton.Clicked(gtx) {
								s.App.CurrentScreen = app.ScreenOpenRequest
							}
							btn := material.Button(s.Theme, &s.backButton, "Back")
							btn.Background = widgets.ColorBorder
							btn.Color = s.Theme.Palette.Fg
							btn.TextSize = unit.Sp(12)
							return btn.Layout(gtx)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),

				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.Card(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								l := material.H6(s.Theme, req.Proposal.Title)
								l.Color = s.Theme.Palette.ContrastBg
								return l.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
							layout.Rigid(material.Body1(s.Theme, req.Proposal.Summary).Layout),
							layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(material.Caption(s.Theme, "Promoter: ").Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										l := material.Caption(s.Theme, req.Proposal.Promoter)
										l.Font.Weight = font.Bold
										return l.Layout(gtx)
									}),
									layout.Flexed(1, layout.Spacer{Width: unit.Dp(1)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										btn := material.Button(s.Theme, &s.DocLinkButton, "View Full Text")
										btn.TextSize = unit.Sp(12)
										return btn.Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if req.Policy == nil {
											return layout.Dimensions{}
										}
										btn := material.Button(s.Theme, &s.PolicyLinkButton, "Policy")
										btn.TextSize = unit.Sp(12)
										btn.Background = widgets.ColorWarning
										return btn.Layout(gtx)
									}),
								)
							}),
						)
					})
				}),

				layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.IconLabel(gtx, s.Theme, icons.IconVocSign, "SIGNATURE WORKSPACE", s.Theme.Palette.Fg, unit.Sp(18))
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),

				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.CustomCard(gtx, color.NRGBA{R: 0xF3, G: 0xF6, B: 0xFC, A: 0xFF}, unit.Dp(18), func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if strings.TrimSpace(req.Proposal.LegalStatement) == "" {
									return layout.Dimensions{}
								}
								return layout.Inset{Bottom: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return widgets.Border(gtx, widgets.ColorWarning, func(gtx layout.Context) layout.Dimensions {
										return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return material.Body2(s.Theme, req.Proposal.LegalStatement).Layout(gtx)
										})
									})
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								leftPane := func(gtx layout.Context) layout.Dimensions {
									return widgets.Card(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(material.Subtitle2(s.Theme, "1. Choose Certificate").Layout),
											layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												var children []layout.FlexChild
												if len(groups.Personal) > 0 {
													children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return material.Caption(s.Theme, "PERSONAL").Layout(gtx)
													}))
													for i := range groups.Personal {
														children = append(children, layout.Rigid(s.certPickerRow(groups.Personal[i])))
													}
												}
												if len(groups.Representation) > 0 {
													children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														l := material.Caption(s.Theme, "REPRESENTATION")
														l.Color = widgets.ColorWarning
														return layout.Inset{Top: unit.Dp(10)}.Layout(gtx, l.Layout)
													}))
													for i := range groups.Representation {
														children = append(children, layout.Rigid(s.certPickerRow(groups.Representation[i])))
													}
												}
												return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
											}),
										)
									})
								}
								rightPane := func(gtx layout.Context) layout.Dimensions {
									return widgets.Card(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
										if s.CertEnum.Value == "" {
											return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												return material.Body2(s.Theme, "Select a certificate to review signer data.").Layout(gtx)
											})
										}
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(material.Subtitle2(s.Theme, "2. Verify Signer Data").Layout),
											layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
													layout.Flexed(1, material.Editor(s.Theme, &s.NomEditor, "Name").Layout),
													layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
													layout.Flexed(1, material.Editor(s.Theme, &s.DNIEditor, "DNI/NIE").Layout),
												)
											}),
											layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
													layout.Flexed(1, material.Editor(s.Theme, &s.Cognom1Editor, "Surname 1").Layout),
													layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
													layout.Flexed(1, material.Editor(s.Theme, &s.Cognom2Editor, "Surname 2").Layout),
												)
											}),
											layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
													layout.Rigid(material.Body2(s.Theme, "Birth Date: ").Layout),
													layout.Flexed(1, material.Editor(s.Theme, &s.BirthEditor, "YYYY-MM-DD").Layout),
												)
											}),
											layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												txt := "Personal identity certificate"
												clr := widgets.ColorSuccess
												icon := icons.IconCheck
												if s.selectedInfo.IsRepresentative {
													txt = "Representative certificate"
													clr = widgets.ColorWarning
													icon = icons.IconWarning
													if s.selectedInfo.OrganizationID != "" {
														txt = "Representative cert (Org ID: " + s.selectedInfo.OrganizationID + ")"
													}
												}
												return widgets.Border(gtx, clr, func(gtx layout.Context) layout.Dimensions {
													return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
														return widgets.IconLabel(gtx, s.Theme, icon, txt, clr, unit.Sp(12))
													})
												})
											}),
										)
									})
								}

								isCompact := gtx.Constraints.Max.X < gtx.Dp(900)
								if isCompact {
									return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
										layout.Rigid(leftPane),
										layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
										layout.Rigid(rightPane),
									)
								}

								return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
									layout.Flexed(0.95, leftPane),
									layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
									layout.Flexed(1.05, rightPane),
								)
							}),

							layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
									return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												if s.App.SignStatus == "" {
													l := material.Body2(s.Theme, "Please verify all details. Your signature will be legally binding.")
													l.Color = s.Theme.Palette.Fg
													return l.Layout(gtx)
												}
												return material.Editor(s.Theme, &s.StatusEditor, "").Layout(gtx)
											}),
											layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												btn := material.Button(s.Theme, &s.SignButton, "CONFIRM & SIGN")
												if s.IsSigning || s.CertEnum.Value == "" {
													btn.Background = widgets.ColorBorder
												} else {
													btn.Background = s.Theme.Palette.ContrastBg
												}
												btn.TextSize = unit.Sp(18)
												return btn.Layout(gtx)
											}),
										)
									})
								})
							}),
						)
					})
				}),
			)
		})
	})
}

func (s *RequestDetailsScreen) certPickerRow(id pkcs12store.Identity) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return material.RadioButton(s.Theme, &s.CertEnum, id.ID, id.FriendlyName).Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Left: unit.Dp(35)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										txt := fmt.Sprintf("Issuer: %s", id.Cert.Issuer.CommonName)
										return material.Caption(s.Theme, txt).Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if !time.Now().After(id.Cert.NotAfter) {
											return layout.Dimensions{}
										}
										l := material.Caption(s.Theme, "Expired")
										l.Color = widgets.ColorWarning
										l.Font.Weight = font.Bold
										return l.Layout(gtx)
									}),
								)
							})
						}),
					)
				})
			})
		})
	}
}

func (s *RequestDetailsScreen) layoutPostSign(gtx layout.Context) layout.Dimensions {
	resp := s.App.SignResponse
	return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return widgets.IconLabel(gtx, s.Theme, icons.IconCheck, "SIGNATURE SUCCESSFULLY PROCESSED", widgets.ColorSuccess, unit.Sp(28))
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
					return widgets.CustomCard(gtx, widgets.ColorSurface, unit.Dp(24), func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return widgets.IconLabel(gtx, s.Theme, icons.IconVocSign, "OFFICIAL RECEIPT", s.Theme.Palette.ContrastBg, unit.Sp(14))
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return material.Caption(s.Theme, "RECEIPT IDENTIFIER").Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								e := &widget.Editor{ReadOnly: true}
								e.SetText(s.App.SignStatus)
								return material.Editor(s.Theme, e, "").Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(material.Caption(s.Theme, "SIGNATURE TIMESTAMP").Layout),
											layout.Rigid(material.Body2(s.Theme, resp.SignedAt).Layout),
										)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(24)}.Layout),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(material.Caption(s.Theme, "FORMAT").Layout),
											layout.Rigid(material.Body2(s.Theme, resp.SignatureFormat).Layout),
										)
									}),
								)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
							layout.Rigid(material.Caption(s.Theme, "CANONICAL PAYLOAD DIGEST (SHA256)").Layout),
							layout.Rigid(material.Body2(s.Theme, resp.PayloadCanonicalSHA256).Layout),
						)
					})
				})
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.backButton.Clicked(gtx) {
					s.App.SignResponse = nil
					s.App.SignStatus = ""
					s.App.CurrentScreen = app.ScreenOpenRequest
				}
				return material.Button(s.Theme, &s.backButton, "DONE - BACK TO HOME").Layout(gtx)
			}),
		)
	})
}

func (s *RequestDetailsScreen) findIdentity(id string) *pkcs12store.Identity {
	for i := range s.App.Identities {
		if s.App.Identities[i].ID == id {
			return &s.App.Identities[i]
		}
	}
	for i := range s.App.SystemIdentities {
		if s.App.SystemIdentities[i].ID == id {
			return &s.App.SystemIdentities[i]
		}
	}
	return nil
}
