package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// HMACSigner provides HMAC-SHA256 signing and verification.
type HMACSigner struct {
	key []byte
}

// NewHMACSigner creates a new HMACService using the given key string.
func NewHMACSigner(key string) *HMACSigner {
	return &HMACSigner{key: []byte(key)}
}

// Sign returns a hex-encoded HMAC-SHA256 signature of the provided data.
func (h *HMACSigner) Sign(data []byte) (string, error) {
	mac := hmac.New(sha256.New, h.key)
	mac.Write(data)
	sig := mac.Sum(nil)
	return hex.EncodeToString(sig), nil
}

// Verify returns true if the hex-encoded signature is valid for the provided data.
func (h *HMACSigner) Verify(data []byte, signature string) (bool, error) {
	expected := hmac.New(sha256.New, h.key)
	expected.Write(data)
	expectedMac := expected.Sum(nil)

	mac, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}

	return hmac.Equal(expectedMac, mac), nil
}
