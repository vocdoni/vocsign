package storage

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp       string `json:"timestamp"`
	RequestID       string `json:"requestId"`
	ProposalTitle   string `json:"proposalTitle,omitempty"`
	SignerName      string `json:"signerName,omitempty"`
	SignerDNI       string `json:"signerDni,omitempty"`
	CallbackHost    string `json:"callbackHost"`
	CertFingerprint string `json:"certFingerprint"`
	Status          string `json:"status"`
	Error           string `json:"error,omitempty"`
	ServerAckID     string `json:"serverAckId,omitempty"`
}

type AuditLogger struct {
	mu       sync.Mutex
	filePath string
}

func NewAuditLogger(dir string) (*AuditLogger, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}
	return &AuditLogger{
		filePath: filepath.Join(dir, "audit.jsonl"),
	}, nil
}

func (l *AuditLogger) Log(entry AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now().Format(time.RFC3339)
	log.Printf("DEBUG: Audit log entry: RequestID=%s Status=%s", entry.RequestID, entry.Status)

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write entry: %w", err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	return nil
}

func (l *AuditLogger) ReadAll() ([]AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, fmt.Errorf("failed to open audit file: %w", err)
	}
	defer f.Close()

	var entries []AuditEntry
	dec := json.NewDecoder(f)
	for dec.More() {
		var entry AuditEntry
		if err := dec.Decode(&entry); err != nil {
			// Skip bad entries or return partial?
			// For MVP, just skip
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
