package icons

import (
	"log"

	"gioui.org/widget"
	"golang.org/x/exp/shiny/materialdesign/icons"
)

var (
	IconVocSign      *widget.Icon
	IconOpenRequest  *widget.Icon
	IconCertificates *widget.Icon
	IconAudit        *widget.Icon
	IconScan         *widget.Icon
	IconImport       *widget.Icon
	IconCheck        *widget.Icon
	IconError        *widget.Icon
	IconWarning      *widget.Icon
	IconLaunch       *widget.Icon
)

func init() {
	loadIcon := func(data []byte, name string) *widget.Icon {
		if len(data) == 0 {
			log.Printf("Icon data for %s is empty!", name)
			return nil
		}
		ic, err := widget.NewIcon(data)
		if err != nil {
			log.Printf("Failed to load %s: %v", name, err)
		}
		return ic
	}

	IconVocSign = loadIcon(icons.ActionVerifiedUser, "IconVocSign")
	IconOpenRequest = loadIcon(icons.ActionDescription, "IconOpenRequest")
	IconCertificates = loadIcon(icons.ActionAccountBox, "IconCertificates")
	IconAudit = loadIcon(icons.ActionHistory, "IconAudit")
	IconScan = loadIcon(icons.ActionSearch, "IconScan")
	IconImport = loadIcon(icons.FileFolderOpen, "IconImport")
	IconCheck = loadIcon(icons.ActionCheckCircle, "IconCheck")
	IconError = loadIcon(icons.AlertError, "IconError")
	IconWarning = loadIcon(icons.AlertWarning, "IconWarning")
	IconLaunch = loadIcon(icons.ActionLaunch, "IconLaunch")
}
