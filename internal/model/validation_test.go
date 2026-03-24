package model

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// validSignRequest returns a fully valid SignRequest that passes Validate().
// Tests mutate a single field from this baseline to verify each check.
func validSignRequest() SignRequest {
	nonce16 := make([]byte, 16)
	for i := range nonce16 {
		nonce16[i] = byte(i)
	}
	sha256Hash := make([]byte, 32)
	for i := range sha256Hash {
		sha256Hash[i] = byte(i + 100)
	}

	now := time.Now().UTC()
	return SignRequest{
		Version:   "1.0",
		RequestID: "req-abc-123",
		IssuedAt:  now.Add(-1 * time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339),
		Nonce:     base64.StdEncoding.EncodeToString(nonce16),
		Proposal: Proposal{
			Title: "Test proposal",
			FullText: FullText{
				SHA256: base64.StdEncoding.EncodeToString(sha256Hash),
			},
		},
		Callback: Callback{
			URL:    "https://example.com/callback",
			Method: "POST",
		},
		Organizer: Organizer{
			KID:       "key-1",
			JWKSetURL: "https://example.com/.well-known/jwks.json",
		},
		OrganizerSignature: &OrganizerSignature{
			Format: "JWS",
			Value:  "eyJhbGciOiJSUzI1NiJ9.test.signature",
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *SignRequest)
		wantErr string // substring expected in the error message; empty means no error
	}{
		// --- happy path ---
		{
			name:    "valid request passes",
			modify:  func(r *SignRequest) {},
			wantErr: "",
		},

		// --- version ---
		{
			name:    "wrong version",
			modify:  func(r *SignRequest) { r.Version = "2.0" },
			wantErr: "unsupported version",
		},
		{
			name:    "empty version",
			modify:  func(r *SignRequest) { r.Version = "" },
			wantErr: "unsupported version",
		},

		// --- requestId ---
		{
			name:    "empty requestId",
			modify:  func(r *SignRequest) { r.RequestID = "" },
			wantErr: "missing requestId",
		},

		// --- issuedAt / expiresAt ---
		{
			name:    "invalid issuedAt format",
			modify:  func(r *SignRequest) { r.IssuedAt = "not-a-date" },
			wantErr: "invalid issuedAt",
		},
		{
			name:    "invalid expiresAt format",
			modify:  func(r *SignRequest) { r.ExpiresAt = "not-a-date" },
			wantErr: "invalid expiresAt",
		},
		{
			name: "issuedAt equals expiresAt",
			modify: func(r *SignRequest) {
				ts := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
				r.IssuedAt = ts
				r.ExpiresAt = ts
			},
			wantErr: "issuedAt must be before expiresAt",
		},
		{
			name: "issuedAt after expiresAt",
			modify: func(r *SignRequest) {
				now := time.Now().UTC()
				r.IssuedAt = now.Add(10 * time.Minute).Format(time.RFC3339)
				r.ExpiresAt = now.Add(5 * time.Minute).Format(time.RFC3339)
			},
			wantErr: "issuedAt must be before expiresAt",
		},
		{
			name: "expired request",
			modify: func(r *SignRequest) {
				past := time.Now().UTC().Add(-1 * time.Hour)
				r.IssuedAt = past.Add(-1 * time.Hour).Format(time.RFC3339)
				r.ExpiresAt = past.Format(time.RFC3339)
			},
			wantErr: "request expired",
		},

		// --- nonce ---
		{
			name:    "invalid nonce base64",
			modify:  func(r *SignRequest) { r.Nonce = "%%%invalid%%%" },
			wantErr: "invalid nonce base64",
		},
		{
			name: "nonce too short (15 bytes)",
			modify: func(r *SignRequest) {
				r.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 15))
			},
			wantErr: "nonce length must be between 16 and 32 bytes",
		},
		{
			name: "nonce too long (33 bytes)",
			modify: func(r *SignRequest) {
				r.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 33))
			},
			wantErr: "nonce length must be between 16 and 32 bytes",
		},
		{
			name: "nonce exactly 16 bytes (lower boundary)",
			modify: func(r *SignRequest) {
				r.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 16))
			},
			wantErr: "",
		},
		{
			name: "nonce exactly 32 bytes (upper boundary)",
			modify: func(r *SignRequest) {
				r.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 32))
			},
			wantErr: "",
		},

		// --- proposal ---
		{
			name:    "empty proposal title",
			modify:  func(r *SignRequest) { r.Proposal.Title = "" },
			wantErr: "missing proposal title",
		},
		{
			name:    "empty proposal fullText sha256",
			modify:  func(r *SignRequest) { r.Proposal.FullText.SHA256 = "" },
			wantErr: "missing proposal fullText sha256",
		},
		{
			name: "invalid proposal fullText sha256 base64",
			modify: func(r *SignRequest) {
				r.Proposal.FullText.SHA256 = "%%%invalid%%%"
			},
			wantErr: "invalid proposal fullText sha256 base64",
		},
		{
			name: "proposal fullText sha256 wrong length (31 bytes)",
			modify: func(r *SignRequest) {
				r.Proposal.FullText.SHA256 = base64.StdEncoding.EncodeToString(make([]byte, 31))
			},
			wantErr: "proposal fullText sha256 must be 32 bytes",
		},
		{
			name: "proposal fullText sha256 wrong length (33 bytes)",
			modify: func(r *SignRequest) {
				r.Proposal.FullText.SHA256 = base64.StdEncoding.EncodeToString(make([]byte, 33))
			},
			wantErr: "proposal fullText sha256 must be 32 bytes",
		},

		// --- callback ---
		{
			name:    "callback URL not https (http on remote host)",
			modify:  func(r *SignRequest) { r.Callback.URL = "http://example.com/callback" },
			wantErr: "callback url must be https",
		},
		{
			name:    "callback URL http on localhost allowed",
			modify:  func(r *SignRequest) { r.Callback.URL = "http://localhost:8080/callback" },
			wantErr: "",
		},
		{
			name:    "callback URL http on 127.0.0.1 allowed",
			modify:  func(r *SignRequest) { r.Callback.URL = "http://127.0.0.1:9090/callback" },
			wantErr: "",
		},
		{
			name:    "callback URL https still valid",
			modify:  func(r *SignRequest) { r.Callback.URL = "https://secure.example.com/cb" },
			wantErr: "",
		},
		{
			name:    "callback method not POST",
			modify:  func(r *SignRequest) { r.Callback.Method = "GET" },
			wantErr: "callback method must be POST",
		},
		{
			name:    "callback method empty",
			modify:  func(r *SignRequest) { r.Callback.Method = "" },
			wantErr: "callback method must be POST",
		},

		// --- organizer ---
		{
			name:    "empty organizer kid",
			modify:  func(r *SignRequest) { r.Organizer.KID = "" },
			wantErr: "missing organizer kid",
		},
		{
			name:    "empty organizer jwkSetUrl",
			modify:  func(r *SignRequest) { r.Organizer.JWKSetURL = "" },
			wantErr: "missing organizer jwkSetUrl",
		},
		{
			name: "organizer jwkSetUrl http on remote host",
			modify: func(r *SignRequest) {
				r.Organizer.JWKSetURL = "http://example.com/.well-known/jwks.json"
			},
			wantErr: "organizer jwkSetUrl must be https",
		},
		{
			name: "organizer jwkSetUrl http on localhost allowed",
			modify: func(r *SignRequest) {
				r.Organizer.JWKSetURL = "http://localhost:8080/.well-known/jwks.json"
			},
			wantErr: "",
		},
		{
			name: "organizer jwkSetUrl http on 127.0.0.1 allowed",
			modify: func(r *SignRequest) {
				r.Organizer.JWKSetURL = "http://127.0.0.1:9090/.well-known/jwks.json"
			},
			wantErr: "",
		},

		// --- organizerSignature ---
		{
			name:    "missing organizerSignature (nil)",
			modify:  func(r *SignRequest) { r.OrganizerSignature = nil },
			wantErr: "missing organizerSignature",
		},
		{
			name: "organizerSignature wrong format",
			modify: func(r *SignRequest) {
				r.OrganizerSignature = &OrganizerSignature{Format: "PGP", Value: "abc"}
			},
			wantErr: "organizerSignature format must be JWS",
		},
		{
			name: "organizerSignature empty format",
			modify: func(r *SignRequest) {
				r.OrganizerSignature = &OrganizerSignature{Format: "", Value: "abc"}
			},
			wantErr: "organizerSignature format must be JWS",
		},
		{
			name: "organizerSignature empty value",
			modify: func(r *SignRequest) {
				r.OrganizerSignature = &OrganizerSignature{Format: "JWS", Value: ""}
			},
			wantErr: "missing organizerSignature value",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validSignRequest()
			tc.modify(&r)
			err := r.Validate()

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateBirthDate_Valid(t *testing.T) {
	tests := []string{
		"1990-05-15",
		"1950-01-01",
		"2008-02-29", // leap year
	}
	for _, d := range tests {
		if err := ValidateBirthDate(d); err != nil {
			t.Errorf("ValidateBirthDate(%q) = %v, want nil", d, err)
		}
	}
}

func TestValidateBirthDate_Invalid(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "empty"},
		{"1980-01-01", "default placeholder"},
		{"not-a-date", "format"},
		{"2025-02-29", "invalid date"},
		{"1990-13-01", "invalid date"},
		{"1990-00-15", "invalid date"},
		{"1890-01-01", "too old"},
		{"2020-06-15", "too young"},
		{"2030-01-01", "future"},
	}
	for _, tc := range tests {
		err := ValidateBirthDate(tc.input)
		if err == nil {
			t.Errorf("ValidateBirthDate(%q) = nil, want error containing %q", tc.input, tc.want)
		}
	}
}
