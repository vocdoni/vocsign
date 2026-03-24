package storage

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNewAuditLogger_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir", "nested")
	_, err := NewAuditLogger(dir)
	if err != nil {
		t.Fatalf("NewAuditLogger returned error: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("path exists but is not a directory")
	}
}

func TestLogAndReadAll_SingleEntry(t *testing.T) {
	logger, err := NewAuditLogger(t.TempDir())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	entry := AuditEntry{
		RequestID:       "req-001",
		ProposalTitle:   "Test Proposal",
		SignerName:      "Alice",
		SignerDNI:       "12345678A",
		CallbackHost:    "https://example.com",
		CertFingerprint: "AA:BB:CC",
		Status:          "success",
	}
	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	got := entries[0]
	if got.RequestID != "req-001" {
		t.Errorf("RequestID = %q, want %q", got.RequestID, "req-001")
	}
	if got.ProposalTitle != "Test Proposal" {
		t.Errorf("ProposalTitle = %q, want %q", got.ProposalTitle, "Test Proposal")
	}
	if got.SignerName != "Alice" {
		t.Errorf("SignerName = %q, want %q", got.SignerName, "Alice")
	}
	if got.Status != "success" {
		t.Errorf("Status = %q, want %q", got.Status, "success")
	}
}

func TestLogAndReadAll_MultipleEntries(t *testing.T) {
	logger, err := NewAuditLogger(t.TempDir())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	const count = 5
	for i := range count {
		entry := AuditEntry{
			RequestID:       fmt.Sprintf("req-%03d", i),
			CallbackHost:    "https://example.com",
			CertFingerprint: "FF:FF:FF",
			Status:          "success",
		}
		if err := logger.Log(entry); err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}

	entries, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != count {
		t.Fatalf("expected %d entries, got %d", count, len(entries))
	}

	// Verify order is preserved (insertion order).
	for i, e := range entries {
		want := fmt.Sprintf("req-%03d", i)
		if e.RequestID != want {
			t.Errorf("entry[%d].RequestID = %q, want %q", i, e.RequestID, want)
		}
	}
}

func TestLogSetsTimestamp(t *testing.T) {
	logger, err := NewAuditLogger(t.TempDir())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	entry := AuditEntry{
		RequestID:       "req-ts",
		CallbackHost:    "https://example.com",
		CertFingerprint: "00:00:00",
		Status:          "pending",
	}
	if entry.Timestamp != "" {
		t.Fatal("precondition: Timestamp should be empty before Log")
	}

	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Timestamp == "" {
		t.Error("Timestamp was not set by Log")
	}
}

func TestReadAll_EmptyFile(t *testing.T) {
	logger, err := NewAuditLogger(t.TempDir())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	// Create the file so it exists but is empty.
	f, err := os.Create(logger.filePath)
	if err != nil {
		t.Fatalf("creating empty file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing empty file: %v", err)
	}

	entries, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries from empty file, got %d", len(entries))
	}
}

func TestReadAll_NonExistentFile(t *testing.T) {
	logger, err := NewAuditLogger(t.TempDir())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	// Do not create the file; it should not exist.
	entries, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll should not return error for non-existent file, got: %v", err)
	}
	if entries == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestLogAndReadAll_PreservesFields(t *testing.T) {
	logger, err := NewAuditLogger(t.TempDir())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	original := AuditEntry{
		RequestID:       "req-full",
		ProposalTitle:   "Full Fields Proposal",
		SignerName:      "Bob",
		SignerDNI:       "87654321Z",
		CallbackHost:    "https://callback.test",
		CertFingerprint: "DE:AD:BE:EF",
		Status:          "error",
		Error:           "something went wrong",
		ServerAckID:     "ack-42",
	}
	if err := logger.Log(original); err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	got := entries[0]

	// Timestamp is set by Log, so we only check that it is non-empty.
	if got.Timestamp == "" {
		t.Error("Timestamp should be set")
	}

	checks := []struct {
		field, got, want string
	}{
		{"RequestID", got.RequestID, original.RequestID},
		{"ProposalTitle", got.ProposalTitle, original.ProposalTitle},
		{"SignerName", got.SignerName, original.SignerName},
		{"SignerDNI", got.SignerDNI, original.SignerDNI},
		{"CallbackHost", got.CallbackHost, original.CallbackHost},
		{"CertFingerprint", got.CertFingerprint, original.CertFingerprint},
		{"Status", got.Status, original.Status},
		{"Error", got.Error, original.Error},
		{"ServerAckID", got.ServerAckID, original.ServerAckID},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
}

func TestConcurrentLog(t *testing.T) {
	logger, err := NewAuditLogger(t.TempDir())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	const goroutines = 10
	const entriesPerGoroutine = 20
	totalExpected := goroutines * entriesPerGoroutine

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errCh := make(chan error, totalExpected)

	for g := range goroutines {
		go func(gID int) {
			defer wg.Done()
			for i := range entriesPerGoroutine {
				entry := AuditEntry{
					RequestID:       fmt.Sprintf("g%d-req-%d", gID, i),
					CallbackHost:    "https://concurrent.test",
					CertFingerprint: "CC:CC:CC",
					Status:          "success",
				}
				if err := logger.Log(entry); err != nil {
					errCh <- fmt.Errorf("goroutine %d, entry %d: %w", gID, i, err)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Log error: %v", err)
	}

	entries, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != totalExpected {
		t.Errorf("expected %d entries, got %d", totalExpected, len(entries))
	}

	// Verify no duplicate RequestIDs (each goroutine+index pair is unique).
	seen := make(map[string]bool, totalExpected)
	for _, e := range entries {
		if seen[e.RequestID] {
			t.Errorf("duplicate RequestID: %s", e.RequestID)
		}
		seen[e.RequestID] = true
	}
}

func TestAuditHashChain(t *testing.T) {
	logger, err := NewAuditLogger(t.TempDir())
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	const count = 5
	for i := range count {
		entry := AuditEntry{
			RequestID:       fmt.Sprintf("chain-%03d", i),
			CallbackHost:    "https://example.com",
			CertFingerprint: "AA:BB:CC",
			Status:          "success",
		}
		if err := logger.Log(entry); err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}

	verified, err := logger.Verify()
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if verified != count {
		t.Fatalf("expected %d verified entries, got %d", count, verified)
	}
}

func TestAuditHashChainTampered(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewAuditLogger(dir)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	const count = 3
	for i := range count {
		entry := AuditEntry{
			RequestID:       fmt.Sprintf("tamper-%03d", i),
			CallbackHost:    "https://example.com",
			CertFingerprint: "DD:EE:FF",
			Status:          "success",
		}
		if err := logger.Log(entry); err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}

	// Tamper with the second line (index 1) in the audit file.
	filePath := filepath.Join(dir, "audit.jsonl")
	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("opening audit file: %v", err)
	}
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing audit file: %v", err)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading audit file: %v", err)
	}

	// Corrupt the second entry by replacing its status.
	lines[1] = strings.Replace(lines[1], `"success"`, `"TAMPERED"`, 1)

	if err := os.WriteFile(filePath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("writing tampered file: %v", err)
	}

	verified, err := logger.Verify()
	if err == nil {
		t.Fatal("expected Verify to return an error for tampered file, got nil")
	}
	// The tampered entry is at index 1 (the modification changes line 1's
	// content, so the hash of line 1 no longer matches line 2's prevHash).
	// However, line 1 itself now has different content, so the hash of line 0
	// still matches line 1's *stored* prevHash (which was not changed).
	// The break shows up at index 2 whose prevHash was computed from the
	// original line 1.
	if verified != 2 {
		t.Fatalf("expected failure at index 2, got index %d (err: %v)", verified, err)
	}
}
