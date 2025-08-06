package encoding

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Base64Codec provides Base64-based implementations of the Crypter interface for encoding and decoding.
// NOTE: Base64 is an encoding and not and encryption algorithm but we make it implement the Cipher interface to fulfill the assignment requirements.
type Base64Codec struct{}

// NewBase64Codec returns a new instance of Base64Crypter.
func NewBase64Codec() *Base64Codec {
	return &Base64Codec{}
}

// Encrypt returns the JSON marshalled input value v as a Base64-encoded string.
func (b Base64Codec) Encrypt(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	// If the marshalled value is a string we should get rid of the surrounding quotes.
	str := string(data)
	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		str = str[1 : len(str)-1]
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(str))
	return encoded, nil
}

// Decrypt decodes a Base64-encoded string and attempts to unmarshal it as JSON.
func (b Base64Codec) Decrypt(s string) (any, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	// Try to unmarshal the decoded string as JSON.
	var result any
	if err := json.Unmarshal(decodedBytes, &result); err == nil { // NO ERROR
		return result, nil
	}

	// Otherwise, return the decoded string as is.
	return string(decodedBytes), nil
}
