package screens

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"io"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
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

	LockedOpenFile widget.Clickable

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

	// Fill the entire background with the page bg color
	paint.FillShape(gtx.Ops, s.Theme.Palette.Bg, clip.Rect{Max: gtx.Constraints.Max}.Op())

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Branded header bar — always visible across all wizard steps
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return s.layoutHeader(gtx)
		}),
		// Step content fills remaining space
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			switch s.Step {
			case StepChoice:
				return s.layoutChoicePanel(gtx)
			case StepImportFile:
				return s.layoutImportPanel(gtx)
			case StepScanResults:
				return s.layoutScanResults(gtx)
			default:
				return layout.Dimensions{}
			}
		}),
	)
}

// layoutHeader renders the branded top bar shared by all wizard steps.
func (s *WizardScreen) layoutHeader(gtx layout.Context) layout.Dimensions {
	headerBg := color.NRGBA{R: 0x1E, G: 0x40, B: 0xAF, A: 0xFF}
	paint.FillShape(gtx.Ops, headerBg, clip.Rect{Max: image.Point{X: gtx.Constraints.Max.X, Y: gtx.Dp(72)}}.Op())

	return layout.Inset{Top: unit.Dp(16), Bottom: unit.Dp(16), Left: unit.Dp(32), Right: unit.Dp(32)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				sz := gtx.Dp(unit.Dp(28))
				gtx.Constraints.Min = image.Point{X: sz, Y: sz}
				gtx.Constraints.Max = gtx.Constraints.Min
				return icons.IconVocSign.Layout(gtx, color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF})
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(14)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Label(s.Theme, unit.Sp(20), "Certificate Management Wizard")
				l.Color = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
				l.Font.Weight = font.Bold
				return l.Layout(gtx)
			}),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }),
		)
	})
}

func (s *WizardScreen) handleActions(gtx layout.Context) {
	if s.ScanModeButton.Clicked(gtx) {
		s.ScanInProgress = true
		s.ScanError = ""
		s.Step = StepScanResults
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ERROR: panic while scanning system stores: %v\n%s", r, string(debug.Stack()))
					s.ScanError = fmt.Sprintf("Scan failed unexpectedly: %v", r)
				}
				s.ScanInProgress = false
				s.App.Invalidate()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			s.App.ScanSystemStores(ctx)
		}()
	}

	if s.FileModeButton.Clicked(gtx) {
		s.Step = StepImportFile
	}

	if s.LockedOpenFile.Clicked(gtx) {
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
						continue
					}
					if strings.HasPrefix(id.ID, "file:") {
						path := strings.TrimPrefix(id.ID, "file:")
						file, err := os.Open(path)
						if err != nil {
							continue
						}
						_, err = s.App.Store.Import(ctx, id.FriendlyName, file, []byte(""))
						_ = file.Close()
						if err == nil {
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

// layoutChoicePanel renders the initial step where the user picks scan or file import.
func (s *WizardScreen) layoutChoicePanel(gtx layout.Context) layout.Dimensions {
	isWide := gtx.Constraints.Max.X >= gtx.Dp(760)

	return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(40), Bottom: unit.Dp(40), Left: unit.Dp(32), Right: unit.Dp(32)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			maxW := gtx.Dp(unit.Dp(860))
			if gtx.Constraints.Max.X < maxW {
				maxW = gtx.Constraints.Max.X
			}
			gtx.Constraints.Min.X = maxW
			gtx.Constraints.Max.X = maxW

			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutChoiceHeading(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if s.ConfirmationMsg == "" {
						return layout.Dimensions{}
					}
					return layout.Inset{Bottom: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return widgets.Banner(gtx, s.Theme, widgets.BannerSuccess, s.ConfirmationMsg)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutModeCards(gtx, isWide)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(32)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := widgets.PrimaryButton(s.Theme, &s.FinishButton, "Finish Setup and Start Signing")
								btn.TextSize = unit.Sp(15)
								return btn.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								l := material.Caption(s.Theme, "You can add more certificates later from the Certificates tab.")
								l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
								l.Alignment = text.Middle
								return l.Layout(gtx)
							}),
						)
					})
				}),
			)
		})
	})
}

func (s *WizardScreen) layoutChoiceHeading(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Label(s.Theme, unit.Sp(28), "Add Your Certificates")
			l.Color = s.Theme.Palette.Fg
			l.Font.Weight = font.Bold
			l.Alignment = text.Middle
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Label(s.Theme, unit.Sp(16), "Choose how you want to add your digital certificates to VocSign.\nYou can always add more later from the Certificates tab.")
			l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
			l.Alignment = text.Middle
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(32)}.Layout),
	)
}

func (s *WizardScreen) layoutModeCards(gtx layout.Context, wide bool) layout.Dimensions {
	if wide {
		// Side-by-side cards
		cardW := (gtx.Constraints.Max.X - gtx.Dp(unit.Dp(24))) / 2
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Start}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return s.modeCard(gtx, cardW,
					icons.IconScan,
					"Automatic Scan",
					"Search your operating system, browser profiles (Firefox, Chrome), and PKCS#11 hardware tokens for installed certificates.",
					true,
					&s.ScanModeButton, "Scan System Now",
				)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(24)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return s.modeCard(gtx, cardW,
					icons.IconImport,
					"Open Certificate File",
					"Manually select a .p12 or .pfx certificate file stored on your computer. You will need the file password.",
					false,
					&s.FileModeButton, "Choose File",
				)
			}),
		)
	}

	// Stacked cards for narrow screens
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return s.modeCard(gtx, gtx.Constraints.Max.X,
				icons.IconScan,
				"Automatic Scan",
				"Search your operating system, browser profiles (Firefox, Chrome), and PKCS#11 hardware tokens for installed certificates.",
				true,
				&s.ScanModeButton, "Scan System Now",
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return s.modeCard(gtx, gtx.Constraints.Max.X,
				icons.IconImport,
				"Open Certificate File",
				"Manually select a .p12 or .pfx certificate file stored on your computer. You will need the file password.",
				false,
				&s.FileModeButton, "Choose File",
			)
		}),
	)
}

func (s *WizardScreen) modeCard(gtx layout.Context, cardWidthPx int, icon *widget.Icon, title, description string, recommended bool, click *widget.Clickable, actionLabel string) layout.Dimensions {
	if cardWidthPx > gtx.Constraints.Max.X {
		cardWidthPx = gtx.Constraints.Max.X
	}
	gtx.Constraints.Min.X = cardWidthPx
	gtx.Constraints.Max.X = cardWidthPx

	borderColor := widgets.ColorBorder
	if recommended {
		borderColor = color.NRGBA{R: 0x1E, G: 0x40, B: 0xAF, A: 0xAA}
	}

	return widgets.Border(gtx, borderColor, func(gtx layout.Context) layout.Dimensions {
		return widgets.CustomCard(gtx, widgets.ColorSurface, unit.Dp(24), func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if icon == nil {
								return layout.Dimensions{}
							}
							iconBg := color.NRGBA{R: 0xEE, G: 0xF3, B: 0xFF, A: 0xFF}
							sz := gtx.Dp(unit.Dp(48))
							gtx.Constraints.Min = image.Point{X: sz, Y: sz}
							gtx.Constraints.Max = gtx.Constraints.Min
							paint.FillShape(gtx.Ops, iconBg, clip.Ellipse{Max: image.Point{X: sz, Y: sz}}.Op(gtx.Ops))
							return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								isz := gtx.Dp(unit.Dp(28))
								gtx.Constraints.Min = image.Point{X: isz, Y: isz}
								gtx.Constraints.Max = gtx.Constraints.Min
								return icon.Layout(gtx, s.Theme.Palette.ContrastBg)
							})
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(14)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											l := material.Label(s.Theme, unit.Sp(18), title)
											l.Font.Weight = font.Bold
											l.Color = s.Theme.Palette.Fg
											return l.Layout(gtx)
										}),
										layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											if !recommended {
												return layout.Dimensions{}
											}
											return widgets.Tag(gtx, s.Theme, "Recommended", s.Theme.Palette.ContrastBg)
										}),
									)
								}),
							)
						}),
					)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					l := material.Body2(s.Theme, description)
					l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
					return l.Layout(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					btn := widgets.PrimaryButton(s.Theme, click, actionLabel)
					btn.TextSize = unit.Sp(14)
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.X = 0
						return btn.Layout(gtx)
					})
				}),
			)
		})
	})
}

// layoutScanResults renders the scan step with consistent header and content area.
func (s *WizardScreen) layoutScanResults(gtx layout.Context) layout.Dimensions {
	systemIDs := s.App.SystemIdentitiesSnapshot()
	locked := s.App.LockedP12Snapshot()
	noResults := len(systemIDs) == 0 && len(locked) == 0

	return layout.Inset{Top: unit.Dp(24), Bottom: unit.Dp(24), Left: unit.Dp(32), Right: unit.Dp(32)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return widgets.ConstrainMaxWidth(gtx, widgets.DefaultPageMaxWidth, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutStepHeading(gtx, icons.IconScan, "System Certificate Scan",
						"Certificates found in your OS, browser profiles, and hardware tokens.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					if s.ScanInProgress {
						return s.layoutCenteredState(gtx, "Scanning certificate stores…",
							"Checking your OS keychain, Firefox/Chrome profiles, and PKCS#11 tokens.\nThis may take up to a minute.", "")
					}
					if s.ScanError != "" {
						return s.layoutCenteredState(gtx, "Scan failed", s.ScanError, "Back")
					}
					if noResults {
						return s.layoutCenteredState(gtx, "No new certificates found",
							"No additional certificates were found in browser or system stores.\nTry importing a .p12 file manually.", "Back")
					}
					return s.layoutScanResultsList(gtx, systemIDs)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if len(locked) == 0 {
						return layout.Dimensions{}
					}
					return layout.Inset{Top: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return s.layoutLockedSection(gtx, locked)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if len(systemIDs) == 0 || s.ScanInProgress || s.ScanError != "" {
						return layout.Dimensions{}
					}
					return s.layoutScanActions(gtx)
				}),
			)
		})
	})
}

func (s *WizardScreen) layoutScanResultsList(gtx layout.Context, systemIDs []pkcs12store.Identity) layout.Dimensions {
	return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
		return material.List(s.Theme, &s.ResultsList).Layout(gtx, len(systemIDs), func(gtx layout.Context, index int) layout.Dimensions {
			id := systemIDs[index]
			if _, ok := s.ImportSelects[id.ID]; !ok {
				s.ImportSelects[id.ID] = &widget.Bool{Value: true}
			}
			return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(material.CheckBox(s.Theme, s.ImportSelects[id.ID], "").Layout),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										l := material.Body2(s.Theme, id.FriendlyName)
										l.Font.Weight = font.Medium
										return l.Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Height: unit.Dp(2)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										txt := fmt.Sprintf("Issuer: %s  ·  Expires: %s", id.Cert.Issuer.CommonName, id.Cert.NotAfter.Format("2006-01-02"))
										l := material.Caption(s.Theme, txt)
										l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
										return l.Layout(gtx)
									}),
								)
							}),
						)
					})
				})
			})
		})
	})
}

func (s *WizardScreen) layoutLockedSection(gtx layout.Context, locked []string) layout.Dimensions {
	return widgets.Section(gtx, color.NRGBA{R: 0xFF, G: 0xF8, B: 0xEC, A: 0xFF}, func(gtx layout.Context) layout.Dimensions {
		var lockedList widget.List
		lockedList.Axis = layout.Vertical
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						sz := gtx.Dp(unit.Dp(18))
						gtx.Constraints.Min = image.Point{X: sz, Y: sz}
						gtx.Constraints.Max = gtx.Constraints.Min
						return icons.IconImport.Layout(gtx, widgets.ColorWarning)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Body2(s.Theme, "Password-protected certificates")
						l.Font.Weight = font.Bold
						l.Color = widgets.ColorWarning
						return l.Layout(gtx)
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return material.List(s.Theme, &lockedList).Layout(gtx, len(locked), func(gtx layout.Context, i int) layout.Dimensions {
					return layout.Inset{Bottom: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return widgets.Border(gtx, widgets.ColorBorder, func(gtx layout.Context) layout.Dimensions {
							return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
											layout.Rigid(material.Body2(s.Theme, locked[i]).Layout),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												l := material.Caption(s.Theme, "Requires a password — import manually using Open Certificate File")
												l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
												return l.Layout(gtx)
											}),
										)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										btn := widgets.SecondaryButton(s.Theme, &s.LockedOpenFile, "Open File")
										btn.TextSize = unit.Sp(12)
										return btn.Layout(gtx)
									}),
								)
							})
						})
					})
				})
			}),
		)
	})
}

func (s *WizardScreen) layoutScanActions(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			btn := widgets.PrimaryButton(s.Theme, &s.ImportButton, "Import Selected Certificates")
			return btn.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			btn := widgets.SecondaryButton(s.Theme, &s.BackToChoice, "Back")
			return btn.Layout(gtx)
		}),
	)
}

// layoutImportPanel renders the file import step.
func (s *WizardScreen) layoutImportPanel(gtx layout.Context) layout.Dimensions {
	return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(40), Bottom: unit.Dp(40), Left: unit.Dp(32), Right: unit.Dp(32)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			maxW := gtx.Dp(unit.Dp(620))
			if gtx.Constraints.Max.X < maxW {
				maxW = gtx.Constraints.Max.X
			}
			gtx.Constraints.Min.X = maxW
			gtx.Constraints.Max.X = maxW

			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return s.layoutStepHeading(gtx, icons.IconImport, "Import Certificate File",
						"Select a .p12 or .pfx file and enter its password to add it to VocSign.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if s.ConfirmationMsg == "" {
						return layout.Dimensions{}
					}
					tone := widgets.BannerError
					if strings.Contains(strings.ToLower(s.ConfirmationMsg), "correctly") {
						tone = widgets.BannerSuccess
					}
					return layout.Inset{Bottom: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return widgets.Banner(gtx, s.Theme, tone, s.ConfirmationMsg)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return widgets.Section(gtx, widgets.ColorSurface, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								l := material.Body2(s.Theme, "Certificate file (.p12 / .pfx)")
								l.Font.Weight = font.Medium
								return l.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										btn := widgets.SecondaryButton(s.Theme, &s.BrowseButton, "Browse…")
										return btn.Layout(gtx)
									}),
									layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										label := s.selectedFile
										if label == "" {
											label = "No file selected"
										}
										l := material.Body2(s.Theme, label)
										if label == "No file selected" {
											l.Color = color.NRGBA{R: 0x9E, G: 0xA3, B: 0xB0, A: 0xFF}
										}
										return l.Layout(gtx)
									}),
								)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								l := material.Body2(s.Theme, "Certificate password")
								l.Font.Weight = font.Medium
								return l.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
							layout.Rigid(material.Editor(s.Theme, &s.PassEditor, "Enter password…").Layout),
							layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								l := material.Caption(s.Theme, "Leave blank if the file has no password.")
								l.Color = color.NRGBA{R: 0x9E, G: 0xA3, B: 0xB0, A: 0xFF}
								return l.Layout(gtx)
							}),
						)
					})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							btn := widgets.PrimaryButton(s.Theme, &s.FileImport, "Import Certificate")
							return btn.Layout(gtx)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							btn := widgets.SecondaryButton(s.Theme, &s.FileBack, "Back")
							return btn.Layout(gtx)
						}),
					)
				}),
			)
		})
	})
}

// layoutStepHeading renders a consistent section title used across scan and import steps.
func (s *WizardScreen) layoutStepHeading(gtx layout.Context, icon *widget.Icon, title, subtitle string) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if icon == nil {
						return layout.Dimensions{}
					}
					sz := gtx.Dp(unit.Dp(32))
					gtx.Constraints.Min = image.Point{X: sz, Y: sz}
					gtx.Constraints.Max = gtx.Constraints.Min
					return icon.Layout(gtx, s.Theme.Palette.ContrastBg)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					l := material.Label(s.Theme, unit.Sp(22), title)
					l.Font.Weight = font.Bold
					l.Color = s.Theme.Palette.Fg
					return l.Layout(gtx)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Body2(s.Theme, subtitle)
			l.Color = color.NRGBA{R: 0x5F, G: 0x6E, B: 0x84, A: 0xFF}
			return l.Layout(gtx)
		}),
	)
}

func (s *WizardScreen) layoutCenteredState(gtx layout.Context, title, subtitle, backLabel string) layout.Dimensions {
	gtx.Constraints.Min.Y = gtx.Constraints.Max.Y
	return widgets.CenterInAvailable(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return widgets.EmptyState(gtx, s.Theme, title, subtitle)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if backLabel == "" {
					return layout.Dimensions{}
				}
				return layout.Inset{Top: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						btn := widgets.SecondaryButton(s.Theme, &s.BackToChoice, backLabel)
						return btn.Layout(gtx)
					})
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
