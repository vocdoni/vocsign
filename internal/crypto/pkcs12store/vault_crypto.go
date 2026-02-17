package pkcs12store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func vaultDeriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 4096, 32, sha256.New)
}

func EncryptData(data, password []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := vaultDeriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(append(salt, nonce...), ciphertext...), nil
}

func DecryptData(data, password []byte) ([]byte, error) {
	if len(data) < 16+12 {
		return nil, errors.New("data too short")
	}
	salt := data[:16]
	nonce := data[16:28]
	ciphertext := data[28:]
	key := vaultDeriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
