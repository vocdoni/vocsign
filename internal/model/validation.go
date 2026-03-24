package model

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"
)

func (r *SignRequest) Validate() error {
	if r.Version != "1.0" {
		return errors.New("unsupported version: " + r.Version)
	}
	if r.RequestID == "" {
		return errors.New("missing requestId")
	}

	issuedAt, err := time.Parse(time.RFC3339, r.IssuedAt)
	if err != nil {
		return fmt.Errorf("invalid issuedAt: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid expiresAt: %w", err)
	}
	if !issuedAt.Before(expiresAt) {
		return errors.New("issuedAt must be before expiresAt")
	}
	if expiresAt.Before(time.Now()) {
		return errors.New("request expired")
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(r.Nonce)
	if err != nil {
		return fmt.Errorf("invalid nonce base64: %w", err)
	}
	if len(nonceBytes) < 16 || len(nonceBytes) > 32 {
		return errors.New("nonce length must be between 16 and 32 bytes")
	}

	if r.Proposal.Title == "" {
		return errors.New("missing proposal title")
	}
	if r.Proposal.FullText.SHA256 == "" {
		return errors.New("missing proposal fullText sha256")
	}
	hashBytes, err := base64.StdEncoding.DecodeString(r.Proposal.FullText.SHA256)
	if err != nil {
		return fmt.Errorf("invalid proposal fullText sha256 base64: %w", err)
	}
	if len(hashBytes) != 32 {
		return errors.New("proposal fullText sha256 must be 32 bytes")
	}

	u, err := url.Parse(r.Callback.URL)
	if err != nil {
		return fmt.Errorf("invalid callback url: %w", err)
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return errors.New("callback url must be https")
	}
	if r.Callback.Method != "POST" {
		return errors.New("callback method must be POST")
	}

	if r.Organizer.KID == "" {
		return errors.New("missing organizer kid")
	}
	if r.Organizer.JWKSetURL == "" {
		return errors.New("missing organizer jwkSetUrl")
	}
	jwksURL, err := url.Parse(r.Organizer.JWKSetURL)
	if err != nil {
		return fmt.Errorf("invalid organizer jwkSetUrl: %w", err)
	}
	if jwksURL.Scheme != "https" && jwksURL.Hostname() != "localhost" && jwksURL.Hostname() != "127.0.0.1" {
		return errors.New("organizer jwkSetUrl must be https")
	}

	if r.OrganizerSignature == nil {
		return errors.New("missing organizerSignature")
	}
	if r.OrganizerSignature.Format != "JWS" {
		return errors.New("organizerSignature format must be JWS")
	}
	if r.OrganizerSignature.Value == "" {
		return errors.New("missing organizerSignature value")
	}

	return nil
}

// ValidateBirthDate checks that s is a valid YYYY-MM-DD birth date.
// It rejects the default placeholder "1980-01-01", future dates,
// dates implying age < 16 or > 120, and invalid calendar dates.
func ValidateBirthDate(s string) error {
	if s == "" {
		return fmt.Errorf("birth date is empty")
	}
	if s == "1980-01-01" {
		return fmt.Errorf("birth date is the default placeholder, please enter your real date of birth")
	}
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		return fmt.Errorf("invalid date format, expected YYYY-MM-DD")
	}
	// Verify the parsed date matches the input (catches Feb 30 → Mar 2, etc.)
	if d.Format("2006-01-02") != s {
		return fmt.Errorf("invalid date: %s", s)
	}
	now := time.Now()
	if d.After(now) {
		return fmt.Errorf("birth date is in the future")
	}
	age := now.Year() - d.Year()
	if now.Month() < d.Month() || (now.Month() == d.Month() && now.Day() < d.Day()) {
		age--
	}
	if age < 16 {
		return fmt.Errorf("signer must be at least 16 years old (too young)")
	}
	if age > 120 {
		return fmt.Errorf("birth date implies age over 120 (too old)")
	}
	return nil
}
