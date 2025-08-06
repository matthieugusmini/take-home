package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// AESGCMCipher provides AES-GCM encryption/decryption and implements http.Cipher.
type AESGCMCipher struct {
	aead cipher.AEAD
}

// NewAESGCMCipher creates a new AESGCMCipher from a 16, 24, or 32-byte key (AES-128/192/256).
func NewAESGCMCipher(key []byte) (*AESGCMCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &AESGCMCipher{aead: aead}, nil
}

// Encrypt marshals 'v' to JSON, encrypts, and returns base64(nonce||ciphertext).
func (c *AESGCMCipher) Encrypt(v any) (string, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)
	result := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decodes base64, decrypts, then unmarshals as JSON.
func (c *AESGCMCipher) Decrypt(s string) (any, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	if len(raw) < c.aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	var v any
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return v, nil
}
