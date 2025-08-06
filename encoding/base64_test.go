package encoding_test

import (
	"reflect"
	"testing"

	"github.com/matthieugusmini/take-home/encoding"
)

func TestBase64Codec_EncryptDecrypt(t *testing.T) {
	testCases := []struct {
		name  string
		input any
	}{
		{name: "string", input: "hello world!"},
		{name: "number", input: 3.14},
		{name: "bool", input: true},
		{name: "null", input: nil},
		{name: "object", input: map[string]any{"foo": "bar", "num": 42.0}},
		{name: "array", input: []any{"x", 42.0, true}},
	}
	codec := encoding.NewBase64Codec()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := codec.Encrypt(tc.input)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			decrypted, err := codec.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if !reflect.DeepEqual(tc.input, decrypted) {
				t.Errorf("Decrypted value: %v, expected: %v", decrypted, tc.input)
			}
		})
	}
}
