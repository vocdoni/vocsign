package pkcs12store

import (
	"errors"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var (
	ErrImportPasswordRequired = errors.New("certificate password required")
	ErrImportWrongPassword    = errors.New("certificate password incorrect")
	ErrImportInvalidFile      = errors.New("invalid certificate file")
	ErrImportUnsupported      = errors.New("unsupported certificate format")
	ErrImportDuplicate        = errors.New("certificate already exists")
)

func userImportError(err error) error {
	switch {
	case errors.Is(err, ErrImportPasswordRequired):
		return ErrImportPasswordRequired
	case errors.Is(err, ErrImportWrongPassword):
		return ErrImportWrongPassword
	case errors.Is(err, ErrImportDuplicate):
		return ErrImportDuplicate
	case errors.Is(err, ErrImportInvalidFile):
		return ErrImportInvalidFile
	case errors.Is(err, ErrImportUnsupported):
		return ErrImportUnsupported
	default:
		return err
	}
}

// FriendlyImportError returns a user-facing error message for certificate import failures.
func FriendlyImportError(err error) string {
	switch userImportError(err) {
	case ErrImportPasswordRequired:
		return "This certificate requires a password. Enter the certificate password and try again."
	case ErrImportWrongPassword:
		return "The certificate password is incorrect."
	case ErrImportDuplicate:
		return "This certificate is already imported in your wallet."
	case ErrImportInvalidFile:
		return "The selected file is not a valid .p12/.pfx certificate or is corrupted."
	case ErrImportUnsupported:
		return "The certificate uses an unsupported format or key type."
	default:
		return "Certificate import failed. Please verify the file and password."
	}
}

func isIncorrectPasswordError(err error) bool {
	if errors.Is(err, pkcs12.ErrIncorrectPassword) || errors.Is(err, pkcs12.ErrDecryption) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "decryption password incorrect") ||
		strings.Contains(msg, "incorrect padding")
}

func isLikelyInvalidFileError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not der") ||
		strings.Contains(msg, "syntax error") ||
		strings.Contains(msg, "trailing data") ||
		strings.Contains(msg, "certificate missing") ||
		strings.Contains(msg, "private key missing") ||
		strings.Contains(msg, "error reading p12 data")
}
