package crypto_test

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/matthieugusmini/take-home/crypto"
)

func TestAESCipher_EncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	cipher, err := crypto.NewAESGCMCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	tests := []struct {
		name  string
		value any
	}{
		{"string", "hello world"},
		{"number", float64(42)},
		{"object", map[string]any{"foo": "bar", "num": float64(1)}},
		{"array", []any{float64(1), "two", 3.0}},
		{"nested", map[string]any{"nested": map[string]any{"a": "b"}}},
		{"empty string", ""},
		{"nil", nil},
		{"bool", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := cipher.Encrypt(tc.value)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			dec, err := cipher.Decrypt(enc)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !reflect.DeepEqual(dec, tc.value) {
				t.Errorf("Roundtrip failed.\nGot:  %#v\nWant: %#v", dec, tc.value)
			}
		})
	}
}

func TestAESCipher_DecryptErrors(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, _ := crypto.NewAESGCMCipher(key)

	t.Run("not base64", func(t *testing.T) {
		_, err := cipher.Decrypt("!!!!notbase64")
		if err == nil {
			t.Error("Expected error for bad base64, got nil")
		}
	})

	t.Run("short ciphertext", func(t *testing.T) {
		enc := base64.StdEncoding.EncodeToString([]byte("short"))
		_, err := cipher.Decrypt(enc)
		if err == nil {
			t.Error("Expected error for short ciphertext, got nil")
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		enc, err := cipher.Encrypt("foo")
		if err != nil {
			t.Fatal(err)
		}
		// Corrupt the ciphertext (change last char)
		tampered := enc[:len(enc)-2] + "AA"
		_, err = cipher.Decrypt(tampered)
		if err == nil {
			t.Error("Expected error for tampered ciphertext, got nil")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		enc, err := cipher.Encrypt("foo")
		if err != nil {
			t.Fatal(err)
		}
		badCipher, _ := crypto.NewAESGCMCipher([]byte("11111111111111111111111111111111"))
		_, err = badCipher.Decrypt(enc)
		if err == nil {
			t.Error("Expected error for wrong key, got nil")
		}
	})

	t.Run("not json", func(t *testing.T) {
		// encrypt valid JSON, then tamper ciphertext so it decrypts to invalid JSON
		enc, err := cipher.Encrypt("foo")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(enc)
		if len(raw) > 0 {
			raw[len(raw)-1] ^= 0xFF // flip last byte to likely break JSON
		}
		tampered := base64.StdEncoding.EncodeToString(raw)
		_, err = cipher.Decrypt(tampered)
		if err == nil {
			t.Error("Expected error for non-JSON plaintext, got nil")
		}
	})
}
