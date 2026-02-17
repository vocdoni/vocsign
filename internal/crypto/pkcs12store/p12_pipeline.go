package pkcs12store

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

type decodeAttempt struct {
	data []byte
	pass string
}

type decodeChainFunc func(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error)

type attemptSource interface {
	Build(data []byte, password string) []decodeAttempt
}

// defaultAttemptSource builds a small, deterministic list of decode attempts:
// raw bytes first, then BER-normalized bytes, then BER-normalized with recomputed MAC.
type defaultAttemptSource struct{}

func newDefaultAttemptSource() attemptSource {
	return defaultAttemptSource{}
}

func (defaultAttemptSource) Build(data []byte, password string) []decodeAttempt {
	passwords := append([]string{password}, alternatePasswords(password)...)

	var attempts []decodeAttempt
	seen := make(map[string]struct{})
	add := func(payload []byte, pass string) {
		sum := sha256.Sum256(payload)
		key := fmt.Sprintf("%x:%s", sum, pass)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		attempts = append(attempts, decodeAttempt{data: payload, pass: pass})
	}

	for _, pass := range passwords {
		add(data, pass)
	}

	normalized, err := normalizeBER(data)
	if err != nil {
		return attempts
	}
	for _, pass := range passwords {
		add(normalized, pass)
	}

	// BER normalization can invalidate MAC bytes, so retry with recomputed MAC.
	for _, pass := range passwords {
		if rewritten, err := recomputePFXMAC(normalized, pass); err == nil {
			add(rewritten, pass)
		}
	}

	return attempts
}

func decodeWithAttempts(decode decodeChainFunc, attempts []decodeAttempt, userPassword string) (signer interface{}, cert *x509.Certificate, chain []*x509.Certificate, err error) {
	var lastErr error
	var hasIncorrectPassword bool
	var firstNonPasswordErr error
	for _, attempt := range attempts {
		signer, cert, chain, err = decode(attempt.data, attempt.pass)
		if err == nil {
			return signer, cert, chain, nil
		}
		if isIncorrectPasswordError(err) {
			hasIncorrectPassword = true
		} else if firstNonPasswordErr == nil {
			firstNonPasswordErr = err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("unknown parse error")
	}

	if hasIncorrectPassword && firstNonPasswordErr == nil {
		if strings.TrimSpace(userPassword) == "" {
			return nil, nil, nil, fmt.Errorf("%w", ErrImportPasswordRequired)
		}
		return nil, nil, nil, fmt.Errorf("%w", ErrImportWrongPassword)
	}

	if firstNonPasswordErr != nil {
		if isLikelyInvalidFileError(firstNonPasswordErr) {
			return nil, nil, nil, fmt.Errorf("%w: %v", ErrImportInvalidFile, firstNonPasswordErr)
		}
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrImportUnsupported, firstNonPasswordErr)
	}

	return nil, nil, nil, fmt.Errorf("%w: %v", ErrImportUnsupported, lastErr)
}
