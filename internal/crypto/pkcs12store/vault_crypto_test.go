package pkcs12store

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("hello, this is a round-trip test")
	password := []byte("strong-password")

	encrypted, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	decrypted, err := DecryptData(encrypted, password)
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data does not match original: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptRoundTrip_EmptyData(t *testing.T) {
	plaintext := []byte{}
	password := []byte("password-for-empty")

	encrypted, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptData failed on empty data: %v", err)
	}

	decrypted, err := DecryptData(encrypted, password)
	if err != nil {
		t.Fatalf("DecryptData failed on empty data: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted empty data does not match: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptRoundTrip_LargeData(t *testing.T) {
	plaintext := make([]byte, 1<<20) // 1 MB
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("failed to generate random plaintext: %v", err)
	}
	password := []byte("large-data-password")

	encrypted, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptData failed on 1MB data: %v", err)
	}

	decrypted, err := DecryptData(encrypted, password)
	if err != nil {
		t.Fatalf("DecryptData failed on 1MB data: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted 1MB data does not match original")
	}
}

func TestEncryptProducesDifferentOutput(t *testing.T) {
	plaintext := []byte("same plaintext both times")
	password := []byte("same-password")

	enc1, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("first EncryptData failed: %v", err)
	}

	enc2, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("second EncryptData failed: %v", err)
	}

	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encryptions of the same plaintext produced identical ciphertext; salt/nonce should differ")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	plaintext := []byte("secret data")
	password := []byte("correct-password")

	encrypted, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	_, err = DecryptData(encrypted, []byte("wrong-password"))
	if err == nil {
		t.Fatal("DecryptData with wrong password should have failed but did not")
	}
}

func TestDecryptTruncatedData(t *testing.T) {
	// Data shorter than salt(16) + nonce(12) = 28 bytes must fail.
	shortData := make([]byte, 27)
	if _, err := rand.Read(shortData); err != nil {
		t.Fatalf("failed to generate random short data: %v", err)
	}

	_, err := DecryptData(shortData, []byte("password"))
	if err == nil {
		t.Fatal("DecryptData should fail on data shorter than 28 bytes")
	}

	// Exactly 28 bytes means zero-length ciphertext, which GCM should reject
	// because there is no authentication tag.
	exactData := make([]byte, 28)
	if _, err := rand.Read(exactData); err != nil {
		t.Fatalf("failed to generate 28-byte data: %v", err)
	}

	_, err = DecryptData(exactData, []byte("password"))
	if err == nil {
		t.Fatal("DecryptData should fail on 28-byte data (no GCM tag)")
	}
}

func TestDecryptCorruptedData(t *testing.T) {
	plaintext := []byte("data to corrupt")
	password := []byte("password")

	encrypted, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	// Flip a byte in the ciphertext portion (after salt+nonce, before the tag).
	// The tag occupies the last 16 bytes, so target the ciphertext body.
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	// Index 28 is the first byte of (ciphertext || tag). Flip it.
	corrupted[28] ^= 0xff

	_, err = DecryptData(corrupted, password)
	if err == nil {
		t.Fatal("DecryptData should fail on corrupted ciphertext")
	}
}

func TestDecryptCorruptedTag(t *testing.T) {
	plaintext := []byte("data with tag to corrupt")
	password := []byte("password")

	encrypted, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	// GCM tag is the last 16 bytes. Flip the very last byte.
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[len(corrupted)-1] ^= 0xff

	_, err = DecryptData(corrupted, password)
	if err == nil {
		t.Fatal("DecryptData should fail when GCM auth tag is corrupted")
	}
}

func TestVaultDeriveKey_Deterministic(t *testing.T) {
	password := []byte("deterministic-password")
	salt := []byte("1234567890abcdef") // 16 bytes

	key1 := vaultDeriveKey(password, salt)
	key2 := vaultDeriveKey(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("vaultDeriveKey is not deterministic: same inputs produced different keys")
	}

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key1))
	}
}

func TestVaultDeriveKey_DifferentSalt(t *testing.T) {
	password := []byte("same-password")
	salt1 := []byte("salt-aaaaaaaaaaaa")
	salt2 := []byte("salt-bbbbbbbbbbbb")

	key1 := vaultDeriveKey(password, salt1)
	key2 := vaultDeriveKey(password, salt2)

	if bytes.Equal(key1, key2) {
		t.Fatal("vaultDeriveKey with different salts should produce different keys")
	}
}

func TestEncryptedDataFormat(t *testing.T) {
	plaintext := []byte("format check")
	password := []byte("password")

	encrypted, err := EncryptData(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	// Minimum output length: salt(16) + nonce(12) + GCM tag(16) = 44 bytes,
	// plus the length of the plaintext.
	minLen := 16 + 12 + 16
	if len(encrypted) < minLen {
		t.Fatalf("encrypted output too short: got %d bytes, want at least %d", len(encrypted), minLen)
	}

	expectedLen := 16 + 12 + len(plaintext) + 16
	if len(encrypted) != expectedLen {
		t.Fatalf("encrypted output length mismatch: got %d, want %d (salt=16 + nonce=12 + plaintext=%d + tag=16)",
			len(encrypted), expectedLen, len(plaintext))
	}
}
