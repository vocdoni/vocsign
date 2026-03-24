package widgets

import (
	"image"
	"image/color"
	"strings"
	"unicode"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"golang.org/x/text/unicode/norm"
)

// Autocomplete is a type-to-filter widget: a text editor with a dropdown of
// matching options. It replaces free-text inputs for fields that must contain
// a value from a known list.
type Autocomplete struct {
	Editor   widget.Editor
	Options  []string // all valid options (must be set before first Layout)
	Selected string   // currently selected value (empty = nothing selected)
	ReadOnly bool     // when true, editor is non-interactive

	filtered []string           // options matching current text
	clicks   []widget.Clickable // one clickable per filtered option
	list     widget.List
	maxShow  int  // max visible items
	focused  bool // track whether editor has focus
}

// NewAutocomplete creates an Autocomplete with the given options.
func NewAutocomplete(options []string) *Autocomplete {
	a := &Autocomplete{
		Options: options,
		maxShow: 8,
	}
	a.Editor.SingleLine = true
	a.list.Axis = layout.Vertical
	return a
}

// SetSelected sets the selected value programmatically (e.g., from certificate).
func (a *Autocomplete) SetSelected(s string) {
	a.Selected = s
	a.Editor.SetText(s)
}

// SetOptions updates the available options.
func (a *Autocomplete) SetOptions(options []string) {
	a.Options = options
	if a.Selected != "" {
		valid := false
		for _, o := range options {
			if o == a.Selected {
				valid = true
				break
			}
		}
		if !valid {
			a.Selected = ""
			a.Editor.SetText("")
		}
	}
}

// IsValid returns true if the current editor text matches a valid option.
func (a *Autocomplete) IsValid() bool {
	if a.Selected != "" {
		return true
	}
	text := strings.TrimSpace(a.Editor.Text())
	if text == "" {
		return false
	}
	for _, o := range a.Options {
		if strings.EqualFold(o, text) {
			return true
		}
	}
	return false
}

// Layout renders the autocomplete widget.
func (a *Autocomplete) Layout(gtx layout.Context, th *material.Theme, hint string) layout.Dimensions {
	a.Editor.ReadOnly = a.ReadOnly
	text := a.Editor.Text()

	for i := range a.clicks {
		if i < len(a.filtered) && a.clicks[i].Clicked(gtx) {
			a.Selected = a.filtered[i]
			a.Editor.SetText(a.Selected)
			a.focused = false
		}
	}

	if gtx.Focused(&a.Editor) {
		a.focused = true
	} else {
		a.focused = false
	}

	if a.Selected != "" && text != a.Selected {
		a.Selected = ""
	}

	a.filtered = a.filter(text)

	for len(a.clicks) < len(a.filtered) {
		a.clicks = append(a.clicks, widget.Clickable{})
	}

	showDropdown := a.focused && !a.ReadOnly && a.Selected == "" && len(a.filtered) > 0

	borderColor := ColorBorder
	if !a.ReadOnly && text != "" && !a.IsValid() && !showDropdown {
		borderColor = ColorError
	} else if a.ReadOnly || a.IsValid() {
		borderColor = ColorSuccess
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.layoutEditorWithBorder(gtx, th, hint, borderColor)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if !showDropdown {
				return layout.Dimensions{}
			}
			return a.layoutDropdown(gtx, th)
		}),
	)
}

func (a *Autocomplete) layoutEditorWithBorder(gtx layout.Context, th *material.Theme, hint string, borderColor color.NRGBA) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			size := image.Point{X: gtx.Dp(3), Y: gtx.Constraints.Min.Y}
			if size.Y == 0 {
				size.Y = gtx.Dp(28)
			}
			paint.FillShape(gtx.Ops, borderColor, clip.Rect{Max: size}.Op())
			return layout.Dimensions{Size: size}
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(4)}.Layout),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			ed := material.Editor(th, &a.Editor, hint)
			return ed.Layout(gtx)
		}),
	)
}

func (a *Autocomplete) layoutDropdown(gtx layout.Context, th *material.Theme) layout.Dimensions {
	n := len(a.filtered)
	if n > a.maxShow {
		n = a.maxShow
	}
	bg := color.NRGBA{R: 0xFA, G: 0xFA, B: 0xFA, A: 0xFF}
	return Border(gtx, ColorBorder, func(gtx layout.Context) layout.Dimensions {
		return CustomCard(gtx, bg, unit.Dp(4), func(gtx layout.Context) layout.Dimensions {
			return material.List(th, &a.list).Layout(gtx, n, func(gtx layout.Context, i int) layout.Dimensions {
				return material.Clickable(gtx, &a.clicks[i], func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(unit.Dp(6)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return material.Body2(th, a.filtered[i]).Layout(gtx)
					})
				})
			})
		})
	})
}

// filter returns options that match the query (case-insensitive, accent-insensitive).
func (a *Autocomplete) filter(query string) []string {
	q := removeDiacritics(strings.ToLower(strings.TrimSpace(query)))
	if q == "" {
		return a.Options
	}
	var result []string
	for _, o := range a.Options {
		normalized := removeDiacritics(strings.ToLower(o))
		if strings.Contains(normalized, q) {
			result = append(result, o)
		}
	}
	return result
}

// removeDiacritics strips accents for comparison (e.g., é→e, ñ→n).
func removeDiacritics(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range norm.NFD.String(s) {
		if !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
