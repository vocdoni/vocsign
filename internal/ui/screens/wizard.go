package screens

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"gioui.org/layout"
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

	// Scrolling
	MainList widget.List

	// StepChoice
	ScanModeButton widget.Clickable
	FileModeButton widget.Clickable
	FinishButton   widget.Clickable

	// StepScanResults
	ResultsList   widget.List
	ImportSelects map[string]*widget.Bool
	ImportButton  widget.Clickable
	BackToChoice  widget.Clickable

	// StepImportFile
	BrowseButton widget.Clickable
	PassEditor   widget.Editor
	FileImport   widget.Clickable
	FileBack     widget.Clickable

	selectedFile string
	importData   []byte

	ConfirmationMsg string
}

func NewWizardScreen(a *app.App, th *material.Theme) *WizardScreen {
	s := &WizardScreen{
		App:           a,
		Theme:         th,
		ImportSelects: make(map[string]*widget.Bool),
	}
	s.ResultsList.Axis = layout.Vertical
	s.MainList.Axis = layout.Vertical
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
}

func (s *WizardScreen) Layout(gtx layout.Context) layout.Dimensions {
	return material.List(s.Theme, &s.MainList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
		switch s.Step {
		case StepChoice:
			return s.layoutChoice(gtx)
		case StepScanResults:
			return s.layoutScanResults(gtx)
		case StepImportFile:
			return s.layoutImportFile(gtx)
		default:
			return layout.Dimensions{}
		}
	})
}

func (s *WizardScreen) layoutChoice(gtx layout.Context) layout.Dimensions {
	if s.ScanModeButton.Clicked(gtx) {
		go func() {
			s.App.ScanSystemStores(context.Background())
			s.Step = StepScanResults
			s.App.Invalidate()
		}()
	}
	if s.FileModeButton.Clicked(gtx) {
		s.Step = StepImportFile
	}
	if s.FinishButton.Clicked(gtx) {
		s.layoutFinish()
	}

	return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return widgets.Card(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.IconLabel(gtx, s.Theme, icons.IconVocSign, "VocSign Setup Wizard", s.Theme.Palette.ContrastBg, unit.Sp(24))
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if s.ConfirmationMsg == "" {
						return layout.Dimensions{}
					}
					l := material.Body2(s.Theme, s.ConfirmationMsg)
					l.Color = widgets.ColorSuccess
					return layout.Inset{Bottom: unit.Dp(16)}.Layout(gtx, l.Layout)
				}),
				layout.Rigid(material.Body1(s.Theme, "How would you like to add your certificates?").Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),

				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
								return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return widgets.IconLabel(gtx, s.Theme, icons.IconScan, "Automatic Scan", s.Theme.Palette.Fg, unit.Sp(18))
										}),
										layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
										layout.Rigid(material.Caption(s.Theme, "Finds certs in Firefox,").Layout),
										layout.Rigid(material.Caption(s.Theme, "Brave, and System.").Layout),
										layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
										layout.Rigid(material.Button(s.Theme, &s.ScanModeButton, "SCAN SYSTEM").Layout),
									)
								})
							})
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(24)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
								return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return widgets.IconLabel(gtx, s.Theme, icons.IconImport, "Manual Import", s.Theme.Palette.Fg, unit.Sp(18))
										}),
										layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
										layout.Rigid(material.Caption(s.Theme, "Select a .p12 or .pfx").Layout),
										layout.Rigid(material.Caption(s.Theme, "file from your disk.").Layout),
										layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
										layout.Rigid(material.Button(s.Theme, &s.FileModeButton, "OPEN FILE").Layout),
									)
								})
							})
						}),
					)
				}),

				layout.Rigid(layout.Spacer{Height: unit.Dp(32)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(s.Theme, &s.FinishButton, "FINISH AND START SIGNING")
					btn.Background = s.Theme.Palette.ContrastBg
					return btn.Layout(gtx)
				}),
			)
		})
	})
}

func (s *WizardScreen) layoutScanResults(gtx layout.Context) layout.Dimensions {
	if s.ImportButton.Clicked(gtx) {
		go func() {
			ctx := context.Background()
			count := 0
			for _, id := range s.App.SystemIdentities {
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
			s.App.Identities = ids
			s.ConfirmationMsg = importSuccessMessage(count)
			s.Step = StepChoice
			s.App.Invalidate()
		}()
	}
	if s.BackToChoice.Clicked(gtx) {
		s.Step = StepChoice
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return widgets.IconLabel(gtx, s.Theme, icons.IconScan, "System Certificates Found", s.Theme.Palette.Fg, unit.Sp(24))
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if len(s.App.SystemIdentities) == 0 {
				return material.Body2(s.Theme, "No new certificates found in system stores.").Layout(gtx)
			}
			var children []layout.FlexChild
			for i := range s.App.SystemIdentities {
				id := s.App.SystemIdentities[i]
				if _, ok := s.ImportSelects[id.ID]; !ok {
					s.ImportSelects[id.ID] = &widget.Bool{Value: true}
				}
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
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
				}))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{}.Layout(gtx,
				layout.Rigid(material.Button(s.Theme, &s.ImportButton, "IMPORT SELECTED").Layout),
				layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
				layout.Rigid(material.Button(s.Theme, &s.BackToChoice, "BACK").Layout),
			)
		}),
	)
}

func (s *WizardScreen) layoutImportFile(gtx layout.Context) layout.Dimensions {
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
					s.App.Identities = ids
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

	return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return widgets.Card(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.IconLabel(gtx, s.Theme, icons.IconImport, "Import from File", s.Theme.Palette.Fg, unit.Sp(24))
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if s.ConfirmationMsg != "" {
						l := material.Body2(s.Theme, s.ConfirmationMsg)
						l.Color = widgets.ColorError
						if strings.Contains(s.ConfirmationMsg, "correctly") {
							l.Color = widgets.ColorSuccess
						}
						return layout.Inset{Bottom: unit.Dp(16)}.Layout(gtx, l.Layout)
					}
					return layout.Dimensions{}
				}),
				layout.Rigid(material.Body2(s.Theme, "Select a .p12 or .pfx certificate file:").Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(material.Button(s.Theme, &s.BrowseButton, "Choose File...").Layout),
						layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
						layout.Rigid(material.Body2(s.Theme, s.selectedFile).Layout),
					)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Rigid(material.Editor(s.Theme, &s.PassEditor, "Password").Layout),
				layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{}.Layout(gtx,
						layout.Rigid(material.Button(s.Theme, &s.FileImport, "IMPORT NOW").Layout),
						layout.Rigid(layout.Spacer{Width: unit.Dp(16)}.Layout),
						layout.Rigid(material.Button(s.Theme, &s.FileBack, "CANCEL").Layout),
					)
				}),
			)
		})
	})
}

func (s *WizardScreen) layoutFinish() {
	go func() {
		ctx := context.Background()
		ids, _ := s.App.Store.List(ctx)
		s.App.Identities = ids
		s.App.CurrentScreen = app.ScreenOpenRequest
		s.App.ShowWizard = false
		s.Reset()
	}()
}
