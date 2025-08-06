// Package http provides HTTP handlers for encryption, decryption, signing, and verification services.
// It abstracts cryptographic operations for use in HTTP servers, enabling interchangeable crypto implementations.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/matthieugusmini/take-home/api"
)

// Cipher defines methods to encrypt and decrypt arbitrary values for use by HTTP handlers.
type Cipher interface {
	Encrypt(v any) (string, error)
	Decrypt(s string) (any, error)
}

// Signer defines methods to sign and verify byte data for use by HTTP handlers.
type Signer interface {
	Sign(data []byte) (string, error)
	Verify(data []byte, signature string) (bool, error)
}

// CryptoAPI provides HTTP endpoints for cryptographic operations using supplied Cipher and Signer implementations.
type CryptoAPI struct {
	cipher Cipher
	signer Signer
}

// NewCryptoAPI creates a new CryptoService using the provided Cipher and Signer.
func NewCryptoAPI(cipher Cipher, signer Signer) *CryptoAPI {
	return &CryptoAPI{
		cipher: cipher,
		signer: signer,
	}
}

// PostEncrypt handles HTTP POST requests for encrypting payload fields using the configured Cipher.
func (cs *CryptoAPI) PostEncrypt(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "Invalid JSON payload"})
		return
	}

	result := make(map[string]any)
	for k, v := range payload {
		encrypted, err := cs.cipher.Encrypt(v)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, api.Error{Error: "Encryption failed"})
			return
		}
		result[k] = encrypted
	}

	writeJSON(w, http.StatusOK, result)
}

// PostDecrypt handles HTTP POST requests for decrypting payload fields using the configured Cipher.
func (cs *CryptoAPI) PostDecrypt(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "Invalid JSON payload"})
		return
	}

	result := make(map[string]any)
	for k, v := range payload {
		strVal, ok := v.(string)
		if !ok {
			result[k] = v
			continue
		}

		dec, err := cs.cipher.Decrypt(strVal)
		if err != nil {
			result[k] = v // keep as is
			continue
		}
		result[k] = dec
	}

	writeJSON(w, http.StatusOK, result)
}

// PostSign handles HTTP POST requests to sign JSON payloads using the configured Signer.
func (cs *CryptoAPI) PostSign(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "Invalid JSON payload"})
		return
	}

	// Canonicalize the JSON by marshaling again to get a canonical representation.
	// This ensures that the signature is computed based on the JSON value rather than its raw string representation,
	// so that the order of properties does not affect the generated signature.
	canon, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "Invalid JSON payload"})
		return
	}

	signature, err := cs.signer.Sign(canon)
	if err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			api.Error{Error: "Failed to sign the given payload"},
		)
		return
	}

	resp := api.SignResponse{
		Signature: signature,
	}

	writeJSON(w, http.StatusOK, resp)
}

// PostVerify handles HTTP POST requests to verify the signature on JSON payloads using the configured Signer.
func (cs *CryptoAPI) PostVerify(w http.ResponseWriter, r *http.Request) {
	var input api.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "Invalid JSON request"})
		return
	}

	// Canonicalize the JSON by marshaling again to get a canonical representation.
	// This ensures that the signature is computed based on the JSON value rather than its raw string representation,
	// so that the order of properties does not affect the generated signature.
	canon, err := json.Marshal(input.Data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "\"data\" is an invalid JSON payload"})
		return
	}

	valid, err := cs.signer.Verify(canon, input.Signature)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, api.Error{Error: "Verification failed"})
		return
	}
	if valid {
		w.WriteHeader(http.StatusNoContent)
	} else {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "Payload/signature mismatch"})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheckjson
}
