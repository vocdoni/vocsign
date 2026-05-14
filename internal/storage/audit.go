package storage

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
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
	PrevHash        string `json:"prevHash"`
}

type AuditLogger struct {
	mu       sync.Mutex
	filePath string
	lastHash string
}

func NewAuditLogger(dir string) (*AuditLogger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}
	l := &AuditLogger{
		filePath: filepath.Join(dir, "audit.jsonl"),
	}
	if err := l.loadLastHash(); err != nil {
		return nil, fmt.Errorf("failed to load last hash: %w", err)
	}
	return l, nil
}

// loadLastHash reads the audit file (if it exists), finds the last non-empty
// line, computes its SHA-256 hash, and stores the result in lastHash. This
// ensures hash-chain continuity across process restarts.
func (l *AuditLogger) loadLastHash() error {
	f, err := os.Open(l.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// No file yet — the chain starts fresh.
			return nil
		}
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("warning: failed to close audit file: %v", err)
		}
	}()

	var lastLine string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lastLine = line
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if lastLine != "" {
		h := sha256.Sum256([]byte(lastLine))
		l.lastHash = hex.EncodeToString(h[:])
	}
	return nil
}

func (l *AuditLogger) Log(entry AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now().Format(time.RFC3339)
	entry.PrevHash = l.lastHash
	log.Printf("DEBUG: Audit log entry: RequestID=%s Status=%s", entry.RequestID, entry.Status)

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	// Update the hash chain with the hash of this entry's JSON bytes.
	h := sha256.Sum256(data)
	l.lastHash = hex.EncodeToString(h[:])

	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open audit file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close() // best-effort on error path; the write error is already being returned
		return fmt.Errorf("failed to write entry: %w", err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		_ = f.Close() // best-effort on error path; the write error is already being returned
		return fmt.Errorf("failed to write newline: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close audit file: %w", err)
	}
	return nil
}

// Verify reads all audit entries and verifies the hash chain. It returns the
// number of verified entries on success, or the index of the first broken link
// together with an error describing the mismatch.
func (l *AuditLogger) Verify() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to open audit file: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("warning: failed to close audit file: %v", err)
		}
	}()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("failed to read audit file: %w", err)
	}

	prevHash := ""
	for i, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return i, fmt.Errorf("entry %d: failed to unmarshal: %w", i, err)
		}
		if entry.PrevHash != prevHash {
			return i, fmt.Errorf("entry %d: hash chain broken: expected prevHash %q, got %q", i, prevHash, entry.PrevHash)
		}
		h := sha256.Sum256([]byte(line))
		prevHash = hex.EncodeToString(h[:])
	}
	return len(lines), nil
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
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("warning: failed to close audit file: %v", cerr)
		}
	}()

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
