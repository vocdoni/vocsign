package screens

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"io"
	"log"
	"runtime/debug"
	"strings"

	"gioui.org/layout"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/vocdoni/gofirma/vocsign/internal/app"
	"github.com/vocdoni/gofirma/vocsign/internal/crypto/pkcs12store"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/icons"
	"github.com/vocdoni/gofirma/vocsign/internal/ui/widgets"
)

func importSuccessMessage(count int) string {
	if count == 1 {
		return "1 certificate imported correctly."
	}
	return fmt.Sprintf("%d certificates imported correctly.", count)
}

type WizardStep int

const (
	StepChoice WizardStep = iota
	StepScanResults
	StepImportFile
)

type WizardScreen struct {
	App   *app.App
	Theme *material.Theme

	Step WizardStep

	ResultsList widget.List

	ScanModeButton widget.Clickable
	FileModeButton widget.Clickable
	FinishButton   widget.Clickable

	ImportSelects map[string]*widget.Bool
	ImportButton  widget.Clickable
	BackToChoice  widget.Clickable

	BrowseButton widget.Clickable
	PassEditor   widget.Editor
	FileImport   widget.Clickable
	FileBack     widget.Clickable

	selectedFile string
	importData   []byte

	ConfirmationMsg string
	ScanInProgress  bool
	ScanError       string
}

func NewWizardScreen(a *app.App, th *material.Theme) *WizardScreen {
	s := &WizardScreen{
		App:           a,
		Theme:         th,
		ImportSelects: make(map[string]*widget.Bool),
	}
	s.ResultsList.Axis = layout.Vertical
	s.PassEditor.SingleLine = true
	s.PassEditor.Mask = '*'
	return s
}

func (s *WizardScreen) Reset() {
	s.Step = StepChoice
	s.importData = nil
	s.selectedFile = ""
	s.ConfirmationMsg = ""
	s.PassEditor.SetText("")
	s.ImportSelects = make(map[string]*widget.Bool)
	s.ScanInProgress = false
	s.ScanError = ""
}

func (s *WizardScreen) Layout(gtx layout.Context) layout.Dimensions {
	s.handleActions(gtx)

	switch s.Step {
	case StepChoice:
		return s.layoutCenteredPanel(gtx, unit.Dp(940), s.layoutChoicePanel)
	case StepImportFile:
		return s.layoutCenteredPanel(gtx, unit.Dp(900), s.layoutImportPanel)
	case StepScanResults:
		return s.layoutScanResults(gtx)
	default:
		return layout.Dimensions{}
	}
}

func (s *WizardScreen) handleActions(gtx layout.Context) {
	if s.ScanModeButton.Clicked(gtx) {
		s.ScanInProgress = true
		s.ScanError = ""
		s.Step = StepScanResults
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ERROR: panic while scanning system stores: %v\\n%s", r, string(debug.Stack()))
					s.ScanError = fmt.Sprintf("Scan failed unexpectedly: %v", r)
				}
				s.ScanInProgress = false
			}()
			s.App.ScanSystemStores(context.Background())
		}()
	}

	if s.FileModeButton.Clicked(gtx) {
		s.Step = StepImportFile
	}

	if s.FinishButton.Clicked(gtx) {
		s.layoutFinish()
	}

	if s.BackToChoice.Clicked(gtx) {
		s.Step = StepChoice
		s.ScanInProgress = false
	}

	if s.BrowseButton.Clicked(gtx) {
		go func() {
			if s.App.Explorer == nil {
				s.ConfirmationMsg = "File picker is unavailable"
				s.App.Invalidate()
				return
			}
			rc, err := s.App.Explorer.ChooseFile()
			if err != nil {
				return
			}
			data, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				s.ConfirmationMsg = "Could not read selected file"
				s.App.Invalidate()
				return
			}
			s.importData = data
			s.selectedFile = "File selected"
			s.ConfirmationMsg = ""
			s.App.Invalidate()
		}()
	}

	if s.FileImport.Clicked(gtx) {
		pass := s.PassEditor.Text()
		if len(s.importData) == 0 {
			s.ConfirmationMsg = "Select a .p12 or .pfx file first"
		} else {
			go func() {
				ctx := context.Background()
				if _, err := s.App.Store.Import(ctx, "Imported Certificate", bytes.NewReader(s.importData), []byte(pass)); err == nil {
					s.importData = nil
					s.selectedFile = ""
					s.PassEditor.SetText("")
					s.ConfirmationMsg = importSuccessMessage(1)
					ids, _ := s.App.Store.List(ctx)
					s.App.SetIdentities(ids)
					s.Step = StepChoice
				} else {
					s.ConfirmationMsg = pkcs12store.FriendlyImportError(err)
				}
				s.App.Invalidate()
			}()
		}
	}

	if s.FileBack.Clicked(gtx) {
		s.Step = StepChoice
	}

	if s.ImportButton.Clicked(gtx) {
		go func() {
			ctx := context.Background()
			count := 0
			for _, id := range s.App.SystemIdentitiesSnapshot() {
				if sel, ok := s.ImportSelects[id.ID]; ok && sel.Value {
					if s.App.Store.Exists(id.Fingerprint256) {
						continue
					}
					if p11, ok := id.Signer.(*pkcs12store.PKCS11Signer); ok {
						if err := s.App.Store.ImportSystem(ctx, id, p11.LibPath, p11.ProfileDir, p11.Slot, p11.ID); err == nil {
							count++
						}
						continue
					}
					if strings.HasPrefix(id.ID, "os:") {
						if err := s.App.Store.ImportSystem(ctx, id, "", "", 0, nil); err == nil {
							count++
						}
					}
				}
			}
			ids, _ := s.App.Store.List(ctx)
			s.App.SetIdentities(ids)
			s.ConfirmationMsg = importSuccessMessage(count)
			s.Step = StepChoice
			s.App.Invalidate()
		}()
	}
}

func (s *WizardScreen) layoutCenteredPanel(gtx layout.Context, width unit.Dp, panel layout.Widget) layout.Dimensions {
	return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
			return centeredMax(gtx, width, panel)
		})
	})
}

func (s *WizardScreen) layoutChoicePanel(gtx layout.Context) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	isCompact := gtx.Constraints.Max.X < gtx.Dp(900)

	return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return widgets.IconLabel(gtx, s.Theme, icons.IconVocSign, "Welcome to VocSign", s.Theme.Palette.ContrastBg, unit.Sp(24))
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.ConfirmationMsg == "" {
					return layout.Dimensions{}
				}
				return centeredMax(gtx, unit.Dp(760), func(gtx layout.Context) layout.Dimensions {
					return widgets.Banner(gtx, s.Theme, widgets.BannerSuccess, s.ConfirmationMsg)
				})
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return centeredLabel(gtx, s.Theme, unit.Sp(18), "Choose how to add your certificates.")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return s.layoutModeCards(gtx, isCompact)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					btn := widgets.SecondaryButton(s.Theme, &s.FinishButton, "Finish and Start Signing")
					return btn.Layout(gtx)
				})
			}),
		)
	})
}

func (s *WizardScreen) layoutModeCards(gtx layout.Context, compact bool) layout.Dimensions {
	if compact {
		cardW := minInt(gtx.Dp(unit.Dp(560)), gtx.Constraints.Max.X)
		return exactWidthPx(gtx, cardW, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.modeCard(gtx, cardW, icons.IconScan, "Automatic Scan", "Find certificates in browser and OS stores.", &s.ScanModeButton, "Scan System")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.modeCard(gtx, cardW, icons.IconImport, "Manual Import", "Import from a .p12/.pfx file.", &s.FileModeButton, "Open File")
				}),
			)
		})
	}

	// Keep a bounded row width and center it as a single unit.
	return centeredMax(gtx, unit.Dp(760), func(gtx layout.Context) layout.Dimensions {
		gapW := gtx.Dp(unit.Dp(18))
		rowW := gtx.Constraints.Max.X
		cardW := (rowW - gapW) / 2
		if cardW < 0 {
			cardW = 0
		}
		rowW = cardW*2 + gapW
		return exactWidthPx(gtx, rowW, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.modeCard(gtx, cardW, icons.IconScan, "Automatic Scan", "Find certificates in browser and OS stores.", &s.ScanModeButton, "Scan System")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(18)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.modeCard(gtx, cardW, icons.IconImport, "Manual Import", "Import from a .p12/.pfx file.", &s.FileModeButton, "Open File")
				}),
			)
		})
	})
}

func (s *WizardScreen) modeCard(gtx layout.Context, cardWidthPx int, icon *widget.Icon, title, subtitle string, click *widget.Clickable, actionLabel string) layout.Dimensions {
	return exactWidthPx(gtx, cardWidthPx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = cardWidthPx
		gtx.Constraints.Max.X = cardWidthPx
		return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if icon == nil {
						return layout.Dimensions{}
					}
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						sz := gtx.Dp(unit.Dp(28))
						gtx.Constraints.Min = image.Point{X: sz, Y: sz}
						gtx.Constraints.Max = gtx.Constraints.Min
						return icon.Layout(gtx, s.Theme.Palette.ContrastBg)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return centeredLabel(gtx, s.Theme, unit.Sp(22), title)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return centeredCaption(gtx, s.Theme, subtitle)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(14)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := widgets.PrimaryButton(s.Theme, click, actionLabel)
					return layout.Center.Layout(gtx, btn.Layout)
				}),
			)
		})
	})
}

func (s *WizardScreen) layoutScanResults(gtx layout.Context) layout.Dimensions {
	systemIDs := s.App.SystemIdentitiesSnapshot()
	noResults := len(systemIDs) == 0

	return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return widgets.ConstrainMaxWidth(gtx, widgets.DefaultPageMaxWidth, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.IconLabel(gtx, s.Theme, icons.IconScan, "System Certificates Found", s.Theme.Palette.ContrastBg, unit.Sp(24))
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					if s.ScanInProgress {
						return s.layoutCenteredState(gtx, "Scanning certificate stores...", "This can take a few seconds depending on your system.", "")
					}
					if s.ScanError != "" {
						return s.layoutCenteredState(gtx, "Scan failed", s.ScanError, "Back")
					}
					if noResults {
						return s.layoutCenteredState(gtx, "No new certificates found", "No additional certificates are available in browser or system stores.", "Back")
					}
					return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
						return material.List(s.Theme, &s.ResultsList).Layout(gtx, len(systemIDs), func(gtx layout.Context, index int) layout.Dimensions {
							id := systemIDs[index]
							if _, ok := s.ImportSelects[id.ID]; !ok {
								s.ImportSelects[id.ID] = &widget.Bool{Value: true}
							}
							return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
									return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(material.CheckBox(s.Theme, s.ImportSelects[id.ID], "").Layout),
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
													layout.Rigid(material.Body2(s.Theme, id.FriendlyName).Layout),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														txt := fmt.Sprintf("Issuer: %s | Expires: %s", id.Cert.Issuer.CommonName, id.Cert.NotAfter.Format("2006-01-02"))
														return material.Caption(s.Theme, txt).Layout(gtx)
													}),
												)
											}),
										)
									})
								})
							})
						})
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if noResults || s.ScanInProgress || s.ScanError != "" {
						return layout.Dimensions{}
					}
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := widgets.PrimaryButton(s.Theme, &s.ImportButton, "Import Selected")
								return btn.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := widgets.SecondaryButton(s.Theme, &s.BackToChoice, "Back")
								return btn.Layout(gtx)
							}),
						)
					})
				}),
			)
		})
	})
}

func (s *WizardScreen) layoutCenteredState(gtx layout.Context, title, subtitle, backLabel string) layout.Dimensions {
	gtx.Constraints.Min.Y = gtx.Constraints.Max.Y
	return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
		return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.EmptyState(gtx, s.Theme, title, subtitle)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if backLabel == "" {
						return layout.Dimensions{}
					}
					return layout.Inset{Top: unit.Dp(14)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						btn := widgets.SecondaryButton(s.Theme, &s.BackToChoice, backLabel)
						return btn.Layout(gtx)
					})
				}),
			)
		})
	})
}

func (s *WizardScreen) layoutImportPanel(gtx layout.Context) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return widgets.IconLabel(gtx, s.Theme, icons.IconImport, "Import from File", s.Theme.Palette.ContrastBg, unit.Sp(24))
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.ConfirmationMsg == "" {
					return layout.Dimensions{}
				}
				tone := widgets.BannerError
				if strings.Contains(strings.ToLower(s.ConfirmationMsg), "correctly") {
					tone = widgets.BannerSuccess
				}
				return centeredMax(gtx, unit.Dp(760), func(gtx layout.Context) layout.Dimensions {
					return widgets.Banner(gtx, s.Theme, tone, s.ConfirmationMsg)
				})
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return centeredLabel(gtx, s.Theme, unit.Sp(16), "Select a .p12 or .pfx certificate file")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return centeredMax(gtx, unit.Dp(700), func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							btn := widgets.SecondaryButton(s.Theme, &s.BrowseButton, "Choose File")
							return btn.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						layout.Flexed(1, material.Body2(s.Theme, s.selectedFile).Layout),
					)
				})
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return centeredMax(gtx, unit.Dp(700), material.Editor(s.Theme, &s.PassEditor, "Password").Layout)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							btn := widgets.PrimaryButton(s.Theme, &s.FileImport, "Import")
							return btn.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							btn := widgets.SecondaryButton(s.Theme, &s.FileBack, "Back")
							return btn.Layout(gtx)
						}),
					)
				})
			}),
		)
	})
}

func (s *WizardScreen) layoutFinish() {
	go func() {
		ctx := context.Background()
		ids, _ := s.App.Store.List(ctx)
		s.App.SetIdentities(ids)
		s.App.CurrentScreen = app.ScreenOpenRequest
		s.App.ShowWizard = false
		s.Reset()
		s.App.Invalidate()
	}()
}

func centeredMax(gtx layout.Context, max unit.Dp, w layout.Widget) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
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

func exactWidthPx(gtx layout.Context, widthPx int, w layout.Widget) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		wpx := widthPx
		if wpx > gtx.Constraints.Max.X {
			wpx = gtx.Constraints.Max.X
		}
		if wpx < 0 {
			wpx = 0
		}
		gtx.Constraints.Min.X = wpx
		gtx.Constraints.Max.X = wpx
		return w(gtx)
	})
}

func centeredLabel(gtx layout.Context, th *material.Theme, size unit.Sp, textValue string) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		l := material.Label(th, size, textValue)
		l.Alignment = text.Middle
		return l.Layout(gtx)
	})
}

func centeredCaption(gtx layout.Context, th *material.Theme, textValue string) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		l := material.Caption(th, textValue)
		l.Alignment = text.Middle
		return l.Layout(gtx)
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
